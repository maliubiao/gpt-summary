Response: The user wants a summary of the functionality of the C++ code in `v8/src/wasm/baseline/liftoff-compiler.cc`. This is part 2 of a 7-part file.

Based on the provided snippet, which seems to focus on handling different WebAssembly operations and their compilation into machine code, I can infer the following:

1. **Instruction Compilation:** The code seems to be responsible for taking WebAssembly instructions and generating corresponding machine code using the `LiftoffAssembler`. This involves manipulating registers, stack, and memory.
2. **Type Handling:** The code explicitly deals with different WebAssembly value types (i32, i64, f32, f64, references, etc.) and ensures correct register allocation and operations based on these types.
3. **Control Flow:**  The code handles control flow constructs like `if`, `else`, `try`, and potentially loops (though not explicitly shown in this snippet). It manages the state of the stack and registers across these control flow changes.
4. **Function Calls:** The code includes mechanisms for calling both C functions (for certain operations or fallbacks) and built-in JavaScript functions.
5. **Exception Handling:** The code demonstrates how WebAssembly exceptions and JavaScript exceptions are caught and handled within the Liftoff compiler.
6. **Memory Access:** The code shows how to access global variables and potentially table elements.
7. **Constant Loading:** The code includes methods for loading constant values of different types.
8. **Null Checks:**  The code shows how explicit null checks are implemented.
9. **Tier-Up:**  There are mentions of "tier-up" checks, suggesting that Liftoff is an initial, faster compiler that can transition to a more optimized compiler later.

Considering the connection to JavaScript, the code interacts with JavaScript in the following ways:

1. **Calling JavaScript Built-ins:** The `CallBuiltin` function is used to invoke JavaScript functions from the WebAssembly code.
2. **Handling JavaScript Exceptions:** The code explicitly handles cases where a JavaScript exception is caught in WebAssembly.
3. **Wasm-to-JS Interop:**  The code handles conversions between WebAssembly `externref` and JavaScript values.

To illustrate with a JavaScript example, let's take the case of calling a JavaScript function from WebAssembly.
这是 `v8/src/wasm/baseline/liftoff-compiler.cc` 文件的第二部分，延续了第一部分的功能，主要负责将 WebAssembly 的操作码（opcodes）翻译成目标机器代码。它定义了 `LiftoffCompiler` 类的方法，这些方法对应于不同的 WebAssembly 指令，并生成执行这些指令所需的汇编代码。

以下是本部分代码的主要功能归纳：

1. **处理控制流指令:**  实现了 `If`, `FallThruTo`, `FinishOneArmedIf`, `FinishTry`, `PopControl` 等方法，用于处理 WebAssembly 中的条件分支 (`if`) 和异常处理 (`try`) 等控制流结构。这些方法负责管理执行状态的跳转、合并和恢复。

2. **生成函数调用代码:**  `GenerateCCall` 和 `GenerateCCallWithStackBuffer` 方法用于调用 C 函数，这通常用于执行一些无法直接用机器码表示的底层操作或者调用外部函数。

3. **实现各种 WebAssembly 运算符:** 包含了大量的 `EmitUnOp` 和 `EmitBinOp` 模板函数，以及针对特定运算符（如 `I32Add`, `F64Sqrt`, `I32DivS` 等）的具体实现。这些函数负责从栈中弹出操作数，执行相应的机器码指令，并将结果压回栈中。

4. **处理类型转换:** `EmitTypeConversion` 方法用于生成 WebAssembly 类型转换指令的机器码，包括整型和浮点型之间的转换，以及带符号和无符号的转换。

5. **处理引用类型操作:**  包含了 `EmitIsNull`, `RefNull`, `RefFunc`, `RefAsNonNull` 等方法，用于处理 WebAssembly 中的引用类型，例如检查空引用、创建空引用和函数引用。

6. **处理局部变量和全局变量:**  `LocalGet`, `LocalSet`, `GlobalGet`, `GlobalSet` 等方法实现了对 WebAssembly 局部变量和全局变量的访问和修改。

7. **处理表操作:** `TableGet` 和 `TableSet` 方法用于生成访问和修改 WebAssembly 表元素的代码。

8. **处理陷阱（Traps）和断言:** `Trap` 和 `AssertNullTypecheck` 等方法用于生成在特定条件下触发 WebAssembly 陷阱或进行类型检查的代码。

9. **处理常量加载:**  `I32Const`, `I64Const`, `F32Const`, `F64Const` 方法用于将常量值加载到栈中。

10. **返回指令:** `DoReturn` 和 `ReturnImpl` 方法用于生成函数返回的机器码。

11. **本地调用优化:**  `TierupCheckOnTailCall` 和 `TierupCheck` 方法涉及到 Liftoff 编译器的分层优化策略，用于在满足一定条件时触发向更优化的编译器过渡。

**与 JavaScript 的关系和示例:**

本部分的代码与 JavaScript 的功能有密切关系，因为它负责生成在 V8 引擎中执行 WebAssembly 代码的机器码。WebAssembly 模块最终会在 JavaScript 环境中加载和执行。

**示例：调用 JavaScript 内置函数**

代码中使用了 `CallBuiltin` 函数来调用 JavaScript 的内置函数。例如，在 `RefFunc` 方法中，调用了 `Builtin::kWasmRefFunc`：

```c++
  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    CallBuiltin(Builtin::kWasmRefFunc,
                MakeSig::Returns(kRef).Params(kI32, kI32),
                {VarState{kI32, static_cast<int>(function_index), 0},
                 VarState{kI32, 0, 0}},
                decoder->position());
    __ PushRegister(kRef, LiftoffRegister(kReturnRegister0));
  }
```

在 JavaScript 中，你可以定义一个 WebAssembly 模块，其中包含一个 `ref.func` 指令，引用模块内部的一个函数：

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic & Version
  0x01, 0x07, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x0a, 0x09,
  0x01, 0x07, 0x00, 0x7c, 0x00, 0x0b, // Example WASM module (simplified)
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

// (假设 WASM 模块定义了一个索引为 0 的函数)
// 在 LiftoffCompiler 中，当遇到 ref.func 0 时，会调用 CallBuiltin(kWasmRefFunc, ...)

```

`Builtin::kWasmRefFunc` 最终会调用 V8 引擎中对应的 JavaScript 代码，创建一个表示 WebAssembly 函数引用的对象，并将其返回。Liftoff 编译器会将这个返回值存储在寄存器中，并通过 `__ PushRegister` 将其压入栈中。

总而言之，这部分代码是 Liftoff 编译器将 WebAssembly 高级指令转换为底层机器码指令的关键组成部分，它直接影响着 WebAssembly 代码在 V8 引擎中的执行效率和正确性，并且通过调用内置函数等方式与 JavaScript 环境进行交互。

Prompt: 
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共7部分，请归纳一下它的功能

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
        [this, fn](LiftoffRegister dst, LiftoffRegister src,
                   LiftoffRegister amount) {
          CallEmitFn(fn, dst, src,
                     amount.is_gp_pair() ? amount.low_gp() : amount.gp());
        },
        fnImm);
  }

  void BinOp(FullDecoder* decoder, WasmOpcode opcode, const Value& lhs,
             const Value& rhs, Value* result) {
    switch (opcode) {
      case kExprI32Add:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_add,
                                        &LiftoffAssembler::emit_i32_addi);
      case kExprI32Sub:
        return EmitBinOp<kI32, kI32>(&LiftoffAssembler::emit_i32_sub);
      case kExprI32Mul:
        return EmitBinOp<kI32, kI32>(&LiftoffAssembler::emit_i32_mul);
      case kExprI32And:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_and,
                                        &LiftoffAssembler::emit_i32_andi);
      case kExprI32Ior:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_or,
                                        &LiftoffAssembler::emit_i32_ori);
      case kExprI32Xor:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_xor,
                                        &LiftoffAssembler::emit_i32_xori);
      case kExprI32Eq:
        return EmitI32CmpOp<kExprI32Eq>(decoder);
      case kExprI32Ne:
        return EmitI32CmpOp<kExprI32Ne>(decoder);
      case kExprI32LtS:
        return EmitI32CmpOp<kExprI32LtS>(decoder);
      case kExprI32LtU:
        return EmitI32CmpOp<kExprI32LtU>(decoder);
      case kExprI32GtS:
        return EmitI32CmpOp<kExprI32GtS>(decoder);
      case kExprI32GtU:
        return EmitI32CmpOp<kExprI32GtU>(decoder);
      case kExprI32LeS:
        return EmitI32CmpOp<kExprI32LeS>(decoder);
      case kExprI32LeU:
        return EmitI32CmpOp<kExprI32LeU>(decoder);
      case kExprI32GeS:
        return EmitI32CmpOp<kExprI32GeS>(decoder);
      case kExprI32GeU:
        return EmitI32CmpOp<kExprI32GeU>(decoder);
      case kExprI64Add:
        return EmitBinOpImm<kI64, kI64>(&LiftoffAssembler::emit_i64_add,
                                        &LiftoffAssembler::emit_i64_addi);
      case kExprI64Sub:
        return EmitBinOp<kI64, kI64>(&LiftoffAssembler::emit_i64_sub);
      case kExprI64Mul:
        return EmitBinOp<kI64, kI64>(&LiftoffAssembler::emit_i64_mul);
      case kExprI64And:
        return EmitBinOpImm<kI64, kI64>(&LiftoffAssembler::emit_i64_and,
                                        &LiftoffAssembler::emit_i64_andi);
      case kExprI64Ior:
        return EmitBinOpImm<kI64, kI64>(&LiftoffAssembler::emit_i64_or,
                                        &LiftoffAssembler::emit_i64_ori);
      case kExprI64Xor:
        return EmitBinOpImm<kI64, kI64>(&LiftoffAssembler::emit_i64_xor,
                                        &LiftoffAssembler::emit_i64_xori);
      case kExprI64Eq:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kEqual));
      case kExprI64Ne:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kNotEqual));
      case kExprI64LtS:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kLessThan));
      case kExprI64LtU:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kUnsignedLessThan));
      case kExprI64GtS:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kGreaterThan));
      case kExprI64GtU:
        return EmitBinOp<kI64, kI32>(BindFirst(
            &LiftoffAssembler::emit_i64_set_cond, kUnsignedGreaterThan));
      case kExprI64LeS:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kLessThanEqual));
      case kExprI64LeU:
        return EmitBinOp<kI64, kI32>(BindFirst(
            &LiftoffAssembler::emit_i64_set_cond, kUnsignedLessThanEqual));
      case kExprI64GeS:
        return EmitBinOp<kI64, kI32>(
            BindFirst(&LiftoffAssembler::emit_i64_set_cond, kGreaterThanEqual));
      case kExprI64GeU:
        return EmitBinOp<kI64, kI32>(BindFirst(
            &LiftoffAssembler::emit_i64_set_cond, kUnsignedGreaterThanEqual));
      case kExprF32Eq:
        return EmitBinOp<kF32, kI32>(
            BindFirst(&LiftoffAssembler::emit_f32_set_cond, kEqual));
      case kExprF32Ne:
        return EmitBinOp<kF32, kI32>(
            BindFirst(&LiftoffAssembler::emit_f32_set_cond, kNotEqual));
      case kExprF32Lt:
        return EmitBinOp<kF32, kI32>(
            BindFirst(&LiftoffAssembler::emit_f32_set_cond, kUnsignedLessThan));
      case kExprF32Gt:
        return EmitBinOp<kF32, kI32>(BindFirst(
            &LiftoffAssembler::emit_f32_set_cond, kUnsignedGreaterThan));
      case kExprF32Le:
        return EmitBinOp<kF32, kI32>(BindFirst(
            &LiftoffAssembler::emit_f32_set_cond, kUnsignedLessThanEqual));
      case kExprF32Ge:
        return EmitBinOp<kF32, kI32>(BindFirst(
            &LiftoffAssembler::emit_f32_set_cond, kUnsignedGreaterThanEqual));
      case kExprF64Eq:
        return EmitBinOp<kF64, kI32>(
            BindFirst(&LiftoffAssembler::emit_f64_set_cond, kEqual));
      case kExprF64Ne:
        return EmitBinOp<kF64, kI32>(
            BindFirst(&LiftoffAssembler::emit_f64_set_cond, kNotEqual));
      case kExprF64Lt:
        return EmitBinOp<kF64, kI32>(
            BindFirst(&LiftoffAssembler::emit_f64_set_cond, kUnsignedLessThan));
      case kExprF64Gt:
        return EmitBinOp<kF64, kI32>(BindFirst(
            &LiftoffAssembler::emit_f64_set_cond, kUnsignedGreaterThan));
      case kExprF64Le:
        return EmitBinOp<kF64, kI32>(BindFirst(
            &LiftoffAssembler::emit_f64_set_cond, kUnsignedLessThanEqual));
      case kExprF64Ge:
        return EmitBinOp<kF64, kI32>(BindFirst(
            &LiftoffAssembler::emit_f64_set_cond, kUnsignedGreaterThanEqual));
      case kExprI32Shl:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_shl,
                                        &LiftoffAssembler::emit_i32_shli);
      case kExprI32ShrS:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_sar,
                                        &LiftoffAssembler::emit_i32_sari);
      case kExprI32ShrU:
        return EmitBinOpImm<kI32, kI32>(&LiftoffAssembler::emit_i32_shr,
                                        &LiftoffAssembler::emit_i32_shri);
      case kExprI32Rol:
        return EmitBitRotationCCall<kI32, ExternalReference::wasm_word32_rol>();
      case kExprI32Ror:
        return EmitBitRotationCCall<kI32, ExternalReference::wasm_word32_ror>();
      case kExprI64Shl:
        return EmitI64Shift(&LiftoffAssembler::emit_i64_shl,
                            &LiftoffAssembler::emit_i64_shli);
      case kExprI64ShrS:
        return EmitI64Shift(&LiftoffAssembler::emit_i64_sar,
                            &LiftoffAssembler::emit_i64_sari);
      case kExprI64ShrU:
        return EmitI64Shift(&LiftoffAssembler::emit_i64_shr,
                            &LiftoffAssembler::emit_i64_shri);
      case kExprI64Rol:
        return EmitBitRotationCCall<kI64, ExternalReference::wasm_word64_rol>();
      case kExprI64Ror:
        return EmitBitRotationCCall<kI64, ExternalReference::wasm_word64_ror>();
      case kExprF32Add:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_add);
      case kExprF32Sub:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_sub);
      case kExprF32Mul:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_mul);
      case kExprF32Div:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_div);
      case kExprF32Min:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_min);
      case kExprF32Max:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_max);
      case kExprF32CopySign:
        return EmitBinOp<kF32, kF32>(&LiftoffAssembler::emit_f32_copysign);
      case kExprF64Add:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_add);
      case kExprF64Sub:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_sub);
      case kExprF64Mul:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_mul);
      case kExprF64Div:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_div);
      case kExprF64Min:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_min);
      case kExprF64Max:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_max);
      case kExprF64CopySign:
        return EmitBinOp<kF64, kF64>(&LiftoffAssembler::emit_f64_copysign);
      case kExprI32DivS:
        return EmitBinOp<kI32, kI32>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapDivByZero);
          // Adding the second trap might invalidate the pointer returned for
          // the first one, thus get both pointers afterwards.
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapDivUnrepresentable);
          Label* div_by_zero = out_of_line_code_.end()[-2].label.get();
          Label* div_unrepresentable = out_of_line_code_.end()[-1].label.get();
          __ emit_i32_divs(dst.gp(), lhs.gp(), rhs.gp(), div_by_zero,
                           div_unrepresentable);
        });
      case kExprI32DivU:
        return EmitBinOp<kI32, kI32>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          Label* div_by_zero =
              AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapDivByZero);
          __ emit_i32_divu(dst.gp(), lhs.gp(), rhs.gp(), div_by_zero);
        });
      case kExprI32RemS:
        return EmitBinOp<kI32, kI32>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          Label* rem_by_zero =
              AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapRemByZero);
          __ emit_i32_rems(dst.gp(), lhs.gp(), rhs.gp(), rem_by_zero);
        });
      case kExprI32RemU:
        return EmitBinOp<kI32, kI32>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          Label* rem_by_zero =
              AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapRemByZero);
          __ emit_i32_remu(dst.gp(), lhs.gp(), rhs.gp(), rem_by_zero);
        });
      case kExprI64DivS:
        return EmitBinOp<kI64, kI64>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapDivByZero);
          // Adding the second trap might invalidate the pointer returned for
          // the first one, thus get both pointers afterwards.
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapDivUnrepresentable);
          Label* div_by_zero = out_of_line_code_.end()[-2].label.get();
          Label* div_unrepresentable = out_of_line_code_.end()[-1].label.get();
          if (!__ emit_i64_divs(dst, lhs, rhs, div_by_zero,
                                div_unrepresentable)) {
            ExternalReference ext_ref = ExternalReference::wasm_int64_div();
            EmitDivOrRem64CCall(dst, lhs, rhs, ext_ref, div_by_zero,
                                div_unrepresentable);
          }
        });
      case kExprI64DivU:
        return EmitBinOp<kI64, kI64>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          Label* div_by_zero =
              AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapDivByZero);
          if (!__ emit_i64_divu(dst, lhs, rhs, div_by_zero)) {
            ExternalReference ext_ref = ExternalReference::wasm_uint64_div();
            EmitDivOrRem64CCall(dst, lhs, rhs, ext_ref, div_by_zero);
          }
        });
      case kExprI64RemS:
        return EmitBinOp<kI64, kI64>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          Label* rem_by_zero =
              AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapRemByZero);
          if (!__ emit_i64_rems(dst, lhs, rhs, rem_by_zero)) {
            ExternalReference ext_ref = ExternalReference::wasm_int64_mod();
            EmitDivOrRem64CCall(dst, lhs, rhs, ext_ref, rem_by_zero);
          }
        });
      case kExprI64RemU:
        return EmitBinOp<kI64, kI64>([this, decoder](LiftoffRegister dst,
                                                     LiftoffRegister lhs,
                                                     LiftoffRegister rhs) {
          Label* rem_by_zero =
              AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapRemByZero);
          if (!__ emit_i64_remu(dst, lhs, rhs, rem_by_zero)) {
            ExternalReference ext_ref = ExternalReference::wasm_uint64_mod();
            EmitDivOrRem64CCall(dst, lhs, rhs, ext_ref, rem_by_zero);
          }
        });
      case kExprRefEq: {
#if defined(V8_COMPRESS_POINTERS)
        // In pointer compression, we smi-corrupt (the upper bits of a
        // Smi are arbitrary). So, we should only compare the lower 32 bits.
        return EmitBinOp<kRefNull, kI32>(
            BindFirst(&LiftoffAssembler::emit_i32_set_cond, kEqual));
#else
        return EmitBinOp<kRefNull, kI32>(
            BindFirst(&LiftoffAssembler::emit_ptrsize_set_cond, kEqual));
#endif
      }

      default:
        UNREACHABLE();
    }
  }

  void TraceInstruction(FullDecoder* decoder, uint32_t markid) {
#if V8_TARGET_ARCH_X64
    __ emit_trace_instruction(markid);
#endif
  }

  void I32Const(FullDecoder* decoder, Value* result, int32_t value) {
    __ PushConstant(kI32, value);
  }

  void I64Const(FullDecoder* decoder, Value* result, int64_t value) {
    // The {VarState} stores constant values as int32_t, thus we only store
    // 64-bit constants in this field if it fits in an int32_t. Larger values
    // cannot be used as immediate value anyway, so we can also just put them in
    // a register immediately.
    int32_t value_i32 = static_cast<int32_t>(value);
    if (value_i32 == value) {
      __ PushConstant(kI64, value_i32);
    } else {
      LiftoffRegister reg = __ GetUnusedRegister(reg_class_for(kI64), {});
      __ LoadConstant(reg, WasmValue(value));
      __ PushRegister(kI64, reg);
    }
  }

  void F32Const(FullDecoder* decoder, Value* result, float value) {
    LiftoffRegister reg = __ GetUnusedRegister(kFpReg, {});
    __ LoadConstant(reg, WasmValue(value));
    __ PushRegister(kF32, reg);
  }

  void F64Const(FullDecoder* decoder, Value* result, double value) {
    LiftoffRegister reg = __ GetUnusedRegister(kFpReg, {});
    __ LoadConstant(reg, WasmValue(value));
    __ PushRegister(kF64, reg);
  }

  void RefNull(FullDecoder* decoder, ValueType type, Value*) {
    LiftoffRegister null = __ GetUnusedRegister(kGpReg, {});
    LoadNullValue(null.gp(), type);
    __ PushRegister(type.kind(), null);
  }

  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    CallBuiltin(Builtin::kWasmRefFunc,
                MakeSig::Returns(kRef).Params(kI32, kI32),
                {VarState{kI32, static_cast<int>(function_index), 0},
                 VarState{kI32, 0, 0}},
                decoder->position());
    __ PushRegister(kRef, LiftoffRegister(kReturnRegister0));
  }

  void RefAsNonNull(FullDecoder* decoder, const Value& arg, Value* result) {
    // The decoder only calls this function if the type is nullable.
    DCHECK(arg.type.is_nullable());
    LiftoffRegList pinned;
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit ||
        IsSubtypeOf(kWasmI31Ref.AsNonNull(), arg.type, decoder->module_) ||
        !arg.type.use_wasm_null()) {
      // Use an explicit null check if
      // (1) we cannot use trap handler or
      // (2) the object might be a Smi or
      // (3) the object might be a JS object.
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, arg.type);
    } else if (!v8_flags.experimental_wasm_skip_null_checks) {
      // Otherwise, load the word after the map word.
      static_assert(WasmStruct::kHeaderSize > kTaggedSize);
      static_assert(WasmArray::kHeaderSize > kTaggedSize);
      static_assert(WasmInternalFunction::kHeaderSize > kTaggedSize);
      LiftoffRegister dst = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      uint32_t protected_load_pc = 0;
      __ Load(dst, obj.gp(), no_reg, wasm::ObjectAccess::ToTagged(kTaggedSize),
              LoadType::kI32Load, &protected_load_pc);
      RegisterProtectedInstruction(decoder, protected_load_pc);
    }
    __ PushRegister(kRef, obj);
  }

  void Drop(FullDecoder* decoder) { __ DropValues(1); }

  V8_NOINLINE V8_PRESERVE_MOST void TraceFunctionExit(FullDecoder* decoder) {
    CODE_COMMENT("trace function exit");
    // Before making the runtime call, spill all cache registers.
    __ SpillAllRegisters();

    // Store the return value if there is exactly one. Multiple return values
    // are not handled yet.
    size_t num_returns = decoder->sig_->return_count();
    // Put the parameter in its place.
    WasmTraceExitDescriptor descriptor;
    DCHECK_EQ(0, descriptor.GetStackParameterCount());
    DCHECK_EQ(1, descriptor.GetRegisterParameterCount());
    Register param_reg = descriptor.GetRegisterParameter(0);
    if (num_returns == 1) {
      auto& return_slot = __ cache_state()->stack_state.back();
      if (return_slot.is_const()) {
        __ Spill(&return_slot);
      }
      DCHECK(return_slot.is_stack());
      __ LoadSpillAddress(param_reg, return_slot.offset(), return_slot.kind());
    } else {
      // Make sure to pass a "valid" parameter (Smi::zero()).
      LoadSmi(LiftoffRegister{param_reg}, 0);
    }

    source_position_table_builder_.AddPosition(
        __ pc_offset(), SourcePosition(decoder->position()), false);
    __ CallBuiltin(Builtin::kWasmTraceExit);
    DefineSafepoint();
  }

  void TierupCheckOnTailCall(FullDecoder* decoder) {
    if (!dynamic_tiering()) return;
    TierupCheck(decoder, decoder->position(),
                __ pc_offset() + kTierUpCostForFunctionEntry);
  }

  void DoReturn(FullDecoder* decoder, uint32_t /* drop values */) {
    ReturnImpl(decoder);
  }

  void ReturnImpl(FullDecoder* decoder) {
    if (V8_UNLIKELY(v8_flags.trace_wasm)) TraceFunctionExit(decoder);
    // A function returning an uninhabitable type can't ever actually reach
    // a {ret} instruction (it can only return by throwing or trapping). So
    // if we do get here, there must have been a bug. Crash to flush it out.
    base::Vector<const ValueType> returns = decoder->sig_->returns();
    if (V8_UNLIKELY(std::any_of(
            returns.begin(), returns.end(),
            [](const ValueType type) { return type.is_uninhabited(); }))) {
      __ Abort(AbortReason::kUninhabitableType);
      return;
    }
    if (dynamic_tiering()) {
      TierupCheck(decoder, decoder->position(),
                  __ pc_offset() + kTierUpCostForFunctionEntry);
    }
    size_t num_returns = decoder->sig_->return_count();
    if (num_returns > 0) __ MoveToReturnLocations(decoder->sig_, descriptor_);
    if (v8_flags.experimental_wasm_growable_stacks) {
      __ CheckStackShrink();
    }
    __ LeaveFrame(StackFrame::WASM);
    __ DropStackSlotsAndRet(
        static_cast<uint32_t>(descriptor_->ParameterSlotCount()));
  }

  void LocalGet(FullDecoder* decoder, Value* result,
                const IndexImmediate& imm) {
    auto local_slot = __ cache_state()->stack_state[imm.index];
    __ cache_state()->stack_state.emplace_back(
        local_slot.kind(), __ NextSpillOffset(local_slot.kind()));
    auto* slot = &__ cache_state()->stack_state.back();
    if (local_slot.is_reg()) {
      __ cache_state()->inc_used(local_slot.reg());
      slot->MakeRegister(local_slot.reg());
    } else if (local_slot.is_const()) {
      slot->MakeConstant(local_slot.i32_const());
    } else {
      DCHECK(local_slot.is_stack());
      auto rc = reg_class_for(local_slot.kind());
      LiftoffRegister reg = __ GetUnusedRegister(rc, {});
      __ cache_state()->inc_used(reg);
      slot->MakeRegister(reg);
      __ Fill(reg, local_slot.offset(), local_slot.kind());
    }
  }

  void LocalSetFromStackSlot(VarState* dst_slot, uint32_t local_index) {
    auto& state = *__ cache_state();
    auto& src_slot = state.stack_state.back();
    ValueKind kind = dst_slot->kind();
    if (dst_slot->is_reg()) {
      LiftoffRegister slot_reg = dst_slot->reg();
      if (state.get_use_count(slot_reg) == 1) {
        __ Fill(dst_slot->reg(), src_slot.offset(), kind);
        return;
      }
      state.dec_used(slot_reg);
      dst_slot->MakeStack();
    }
    DCHECK(CompatibleStackSlotTypes(kind, __ local_kind(local_index)));
    RegClass rc = reg_class_for(kind);
    LiftoffRegister dst_reg = __ GetUnusedRegister(rc, {});
    __ Fill(dst_reg, src_slot.offset(), kind);
    *dst_slot = VarState(kind, dst_reg, dst_slot->offset());
    __ cache_state()->inc_used(dst_reg);
  }

  void LocalSet(uint32_t local_index, bool is_tee) {
    auto& state = *__ cache_state();
    auto& source_slot = state.stack_state.back();
    auto& target_slot = state.stack_state[local_index];
    switch (source_slot.loc()) {
      case kRegister:
        if (target_slot.is_reg()) state.dec_used(target_slot.reg());
        target_slot.Copy(source_slot);
        if (is_tee) state.inc_used(target_slot.reg());
        break;
      case kIntConst:
        if (target_slot.is_reg()) state.dec_used(target_slot.reg());
        target_slot.Copy(source_slot);
        break;
      case kStack:
        LocalSetFromStackSlot(&target_slot, local_index);
        break;
    }
    if (!is_tee) __ cache_state()->stack_state.pop_back();
  }

  void LocalSet(FullDecoder* decoder, const Value& value,
                const IndexImmediate& imm) {
    LocalSet(imm.index, false);
  }

  void LocalTee(FullDecoder* decoder, const Value& value, Value* result,
                const IndexImmediate& imm) {
    LocalSet(imm.index, true);
  }

  Register GetGlobalBaseAndOffset(const WasmGlobal* global,
                                  LiftoffRegList* pinned, uint32_t* offset) {
    Register addr = pinned->set(__ GetUnusedRegister(kGpReg, {})).gp();
    if (global->mutability && global->imported) {
      LOAD_TAGGED_PTR_INSTANCE_FIELD(addr, ImportedMutableGlobals, *pinned);
      int field_offset =
          wasm::ObjectAccess::ElementOffsetInTaggedFixedAddressArray(
              global->index);
      __ LoadFullPointer(addr, addr, field_offset);
      *offset = 0;
#ifdef V8_ENABLE_SANDBOX
      __ DecodeSandboxedPointer(addr);
#endif
    } else {
      LOAD_INSTANCE_FIELD(addr, GlobalsStart, kSystemPointerSize, *pinned);
      *offset = global->offset;
    }
      return addr;
  }

  void GetBaseAndOffsetForImportedMutableExternRefGlobal(
      const WasmGlobal* global, LiftoffRegList* pinned, Register* base,
      Register* offset) {
    Register globals_buffer =
        pinned->set(__ GetUnusedRegister(kGpReg, *pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(globals_buffer,
                                   ImportedMutableGlobalsBuffers, *pinned);
    *base = globals_buffer;
    __ LoadTaggedPointer(
        *base, globals_buffer, no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(global->offset));

    // For the offset we need the index of the global in the buffer, and
    // then calculate the actual offset from the index. Load the index from
    // the ImportedMutableGlobals array of the instance.
    Register imported_mutable_globals =
        pinned->set(__ GetUnusedRegister(kGpReg, *pinned)).gp();

    LOAD_TAGGED_PTR_INSTANCE_FIELD(imported_mutable_globals,
                                   ImportedMutableGlobals, *pinned);
    *offset = imported_mutable_globals;
    int field_offset =
        wasm::ObjectAccess::ElementOffsetInTaggedFixedAddressArray(
            global->index);
    __ Load(LiftoffRegister(*offset), imported_mutable_globals, no_reg,
            field_offset, LoadType::kI32Load);
    __ emit_i32_shli(*offset, *offset, kTaggedSizeLog2);
    __ emit_i32_addi(*offset, *offset,
                     wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(0));
  }

  void GlobalGet(FullDecoder* decoder, Value* result,
                 const GlobalIndexImmediate& imm) {
    const auto* global = &env_->module->globals[imm.index];
    ValueKind kind = global->type.kind();
    if (!CheckSupportedType(decoder, kind, "global")) {
      return;
    }

    if (is_reference(kind)) {
      if (global->mutability && global->imported) {
        LiftoffRegList pinned;
        Register base = no_reg;
        Register offset = no_reg;
        GetBaseAndOffsetForImportedMutableExternRefGlobal(global, &pinned,
                                                          &base, &offset);
        __ LoadTaggedPointer(base, base, offset, 0);
        __ PushRegister(kind, LiftoffRegister(base));
        return;
      }

      LiftoffRegList pinned;
      Register globals_buffer =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      LOAD_TAGGED_PTR_INSTANCE_FIELD(globals_buffer, TaggedGlobalsBuffer,
                                     pinned);
      Register value = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      __ LoadTaggedPointer(value, globals_buffer, no_reg,
                           wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                               imm.global->offset));
      __ PushRegister(kind, LiftoffRegister(value));
      return;
    }
    LiftoffRegList pinned;
    uint32_t offset = 0;
    Register addr = GetGlobalBaseAndOffset(global, &pinned, &offset);
    LiftoffRegister value =
        pinned.set(__ GetUnusedRegister(reg_class_for(kind), pinned));
    LoadType type = LoadType::ForValueKind(kind);
    __ Load(value, addr, no_reg, offset, type, nullptr, false);
    __ PushRegister(kind, value);
  }

  void GlobalSet(FullDecoder* decoder, const Value&,
                 const GlobalIndexImmediate& imm) {
    auto* global = &env_->module->globals[imm.index];
    ValueKind kind = global->type.kind();
    if (!CheckSupportedType(decoder, kind, "global")) {
      return;
    }

    if (is_reference(kind)) {
      if (global->mutability && global->imported) {
        LiftoffRegList pinned;
        Register value = pinned.set(__ PopToRegister(pinned)).gp();
        Register base = no_reg;
        Register offset = no_reg;
        GetBaseAndOffsetForImportedMutableExternRefGlobal(global, &pinned,
                                                          &base, &offset);
        __ StoreTaggedPointer(base, offset, 0, value, pinned);
        return;
      }

      LiftoffRegList pinned;
      Register globals_buffer =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
      LOAD_TAGGED_PTR_INSTANCE_FIELD(globals_buffer, TaggedGlobalsBuffer,
                                     pinned);
      Register value = pinned.set(__ PopToRegister(pinned)).gp();
      __ StoreTaggedPointer(globals_buffer, no_reg,
                            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(
                                imm.global->offset),
                            value, pinned);
      return;
    }
    LiftoffRegList pinned;
    uint32_t offset = 0;
    Register addr = GetGlobalBaseAndOffset(global, &pinned, &offset);
    LiftoffRegister reg = pinned.set(__ PopToRegister(pinned));
    StoreType type = StoreType::ForValueKind(kind);
    __ Store(addr, no_reg, offset, reg, type, {}, nullptr, false);
  }

  void TableGet(FullDecoder* decoder, const Value&, Value*,
                const TableIndexImmediate& imm) {
    Register index_high_word = no_reg;
    LiftoffRegList pinned;
    VarState table_index{kI32, static_cast<int>(imm.index), 0};

    // Convert the index to the table to an intptr.
    VarState index = PopIndexToVarState(&index_high_word, &pinned);
    // Trap if any bit in the high word was set.
    CheckHighWordEmptyForTableType(decoder, index_high_word, &pinned);

    ValueType type = imm.table->type;
    bool is_funcref = IsSubtypeOf(type, kWasmFuncRef, env_->module);
    auto stub =
        is_funcref ? Builtin::kWasmTableGetFuncRef : Builtin::kWasmTableGet;

    CallBuiltin(stub, MakeSig::Returns(type.kind()).Params(kI32, kIntPtrKind),
                {table_index, index}, decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    __ PushRegister(type.kind(), LiftoffRegister(kReturnRegister0));
  }

  void TableSet(FullDecoder* decoder, const Value&, const Value&,
                const TableIndexImmediate& imm) {
    Register index_high_word = no_reg;
    LiftoffRegList pinned;
    VarState table_index{kI32, static_cast<int>(imm.index), 0};

    VarState value = __ PopVarState();
    if (value.is_reg()) pinned.set(value.reg());
    // Convert the index to the table to an intptr.
    VarState index = PopIndexToVarState(&index_high_word, &pinned);
    // Trap if any bit in the high word was set.
    CheckHighWordEmptyForTableType(decoder, index_high_word, &pinned);
    VarState extract_shared_part{kI32, 0, 0};

    bool is_funcref = IsSubtypeOf(imm.table->type, kWasmFuncRef, env_->module);
    auto stub =
        is_funcref ? Builtin::kWasmTableSetFuncRef : Builtin::kWasmTableSet;

    CallBuiltin(stub, MakeSig::Params(kI32, kI32, kIntPtrKind, kRefNull),
                {table_index, extract_shared_part, index, value},
                decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  Builtin GetBuiltinForTrapReason(TrapReason reason) {
    switch (reason) {
#define RUNTIME_STUB_FOR_TRAP(trap_reason) \
  case k##trap_reason:                     \
    return Builtin::kThrowWasm##trap_reason;

      FOREACH_WASM_TRAPREASON(RUNTIME_STUB_FOR_TRAP)
#undef RUNTIME_STUB_FOR_TRAP
      default:
        UNREACHABLE();
    }
  }

  void Trap(FullDecoder* decoder, TrapReason reason) {
    Label* trap_label =
        AddOutOfLineTrap(decoder, GetBuiltinForTrapReason(reason));
    __ emit_jump(trap_label);
    __ AssertUnreachable(AbortReason::kUnexpectedReturnFromWasmTrap);
  }

  void AssertNullTypecheckImpl(FullDecoder* decoder, const Value& arg,
                               Value* result, Condition cond) {
    LiftoffRegList pinned;
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapIllegalCast);
    LiftoffRegister null = __ GetUnusedRegister(kGpReg, pinned);
    LoadNullValueForCompare(null.gp(), pinned, arg.type);
    {
      FREEZE_STATE(trapping);
      __ emit_cond_jump(cond, trap_label, kRefNull, obj.gp(), null.gp(),
                        trapping);
    }
    __ PushRegister(kRefNull, obj);
  }

  void AssertNullTypecheck(FullDecoder* decoder, const Value& arg,
                           Value* result) {
    AssertNullTypecheckImpl(decoder, arg, result, kNotEqual);
  }

  void AssertNotNullTypecheck(FullDecoder* decoder, const Value& arg,
                              Value* result) {
    AssertNullTypecheckImpl(decoder, arg, result, kEqual);
  }

  void NopForTestingUnsupportedInLiftoff(FullDecoder* decoder) {
    unsupported(decoder, kOtherReason, "testing opcode");
  }

  void Select(FullDecoder* decoder, const Value& cond, const Value& fval,
              const Value& tval, Value* result) {
    LiftoffRegList pinned;
    Register condition = pinned.set(__ PopToRegister()).gp();
    ValueKind kind = __ cache_state()->stack_state.end()[-1].kind();
    DCHECK(CompatibleStackSlotTypes(
        kind, __ cache_state()->stack_state.end()[-2].kind()));
    LiftoffRegister false_value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister true_value = __ PopToRegister(pinned);
    LiftoffRegister dst = __ GetUnusedRegister(true_value.reg_class(),
                                               {true_val
"""


```