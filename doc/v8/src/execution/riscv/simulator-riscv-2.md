Response: The user wants to understand the functionality of the C++ code snippet provided, which is part 3 of a 5-part file. The file `simulator-riscv.cc` is located within the `v8/src/execution/riscv/` directory. This suggests it's related to the RISC-V architecture simulator within the V8 JavaScript engine.

The code defines several function pointer types (`SimulatorRuntimeCall`, `SimulatorRuntimeCompareCall`, etc.) for calling C++ runtime functions from the simulator. It also includes a `Simulator::SoftwareInterrupt()` function, which seems to handle calls to these runtime functions triggered by specific RISC-V instructions (ebreak/ecall).

Therefore, the core functionality of this part is likely:

1. **Defining interfaces for calling C++ runtime functions from the simulator.** This includes different signatures for regular calls, floating-point calls, and direct API calls.
2. **Implementing the `SoftwareInterrupt()` function to handle calls into the V8 runtime.** This involves:
    - Detecting the type of call (redirected call).
    - Extracting arguments from registers and the stack.
    - Calling the appropriate C++ runtime function using the defined function pointers.
    - Handling return values.
3. **Handling debugging and tracing within the simulator using software interrupts.**  This is indicated by the checks for `ebreak` and handling of watchpoints and tracepoints.
This part of the `simulator-riscv.cc` file focuses on **handling software interrupts** within the RISC-V simulator. Software interrupts are used as a mechanism for the simulated RISC-V code to call into the C++ V8 runtime environment. This allows the simulator to execute built-in JavaScript functions and interact with the V8 engine's internals.

Here's a breakdown of its functionality:

1. **Defining Runtime Call Interfaces:**
    *   It defines various function pointer types (`SimulatorRuntimeCall`, `SimulatorRuntimeCompareCall`, etc.) that represent the signatures of C++ functions within the V8 runtime. These signatures specify how arguments are passed (through registers or stack) and the return type. This creates a standardized way for the simulator to interact with the V8 runtime.

2. **Implementing `Simulator::SoftwareInterrupt()`:**
    *   This function is the core of this section. It's invoked when the simulated RISC-V code executes an `ebreak` or `ecall` instruction, which are used as software interrupts.
    *   **Detecting Runtime Calls:** It checks if the interrupt is a "call runtime redirected" instruction (`rtCallRedirInstr`). This is how the simulated code signals a call to a V8 runtime function.
    *   **Retrieving Target Function and Arguments:** It extracts the address of the C++ runtime function to be called and retrieves the arguments from the simulated RISC-V registers (`a0` - `a7`) and potentially the stack.
    *   **Handling Different Call Types:** It distinguishes between different types of runtime calls:
        *   **Regular Runtime Calls:** Calls that pass arguments in general-purpose registers.
        *   **Floating-Point Runtime Calls:** Calls that involve floating-point arguments passed in floating-point registers.
        *   **Direct API Calls:** Calls to specific V8 API functions.
        *   **Direct Getter Calls:** Calls to object property getter functions.
    *   **Calling the C++ Runtime Function:** Based on the call type, it uses the appropriate function pointer type to call the corresponding C++ function in the V8 runtime.
    *   **Handling Return Values:** It receives the return value from the C++ function and sets the appropriate simulated RISC-V registers (`a0`, `a1`, `fa0`) to reflect the return value.

3. **Supporting Debugging and Tracing:**
    *   The `SoftwareInterrupt()` function also handles `ebreak` instructions with specific codes for debugging purposes.
    *   It allows for setting watchpoints (breakpoints that trigger when a specific condition is met) and tracepoints (breakpoints that log information).
    *   It includes logic to enable/disable tracing and print register values for debugging.

**Relationship to JavaScript Functionality (with JavaScript examples):**

This code is the bridge between the simulated RISC-V execution and the actual execution of JavaScript within V8. When JavaScript code calls a built-in function or performs an operation that requires interaction with V8's internal data structures, the generated RISC-V code within the simulator will often trigger a software interrupt to call a C++ runtime function.

Here are a few examples of how this relates to JavaScript:

*   **`console.log()`:** When JavaScript code executes `console.log("Hello");`, the simulator might encounter an instruction that triggers a software interrupt. The `SoftwareInterrupt()` function would identify this as a call to a specific C++ runtime function responsible for handling console output. The arguments ("Hello") would be passed through simulated registers, and the C++ function would then perform the actual output.

    ```javascript
    console.log("Hello");
    ```

*   **Array Manipulation (e.g., `push()`):** If you have an array and use the `push()` method:

    ```javascript
    const myArray = [1, 2, 3];
    myArray.push(4);
    ```

    Internally, the `push()` operation might involve a software interrupt to call a C++ runtime function that manipulates the array's underlying memory structure within V8.

*   **Object Property Access:** Accessing properties of JavaScript objects can also involve runtime calls, especially for properties with getters or setters.

    ```javascript
    const myObject = {
      get myProperty() {
        return "Value";
      }
    };
    console.log(myObject.myProperty);
    ```

    The access to `myObject.myProperty` would potentially trigger a software interrupt to call the getter function defined in C++. The `SimulatorRuntimeDirectGetterCall` type in the code is specifically for this purpose.

*   **Built-in Math Functions:**  Calling built-in mathematical functions like `Math.sqrt()` or `Math.sin()` might involve floating-point runtime calls handled by the `SimulatorRuntimeFPCall` mechanism.

    ```javascript
    const result = Math.sqrt(9);
    ```

In essence, this part of the simulator provides the mechanism for the simulated RISC-V code, generated from JavaScript, to interact with the underlying V8 JavaScript engine's implementation in C++. The software interrupt is the key trigger that allows this interaction to occur.

Prompt: 
```
这是目录为v8/src/execution/riscv/simulator-riscv.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
into the V8 runtime are based on this very simple interface.
// Note: To be able to return two values from some calls the code in
// runtime.cc uses the ObjectPair which is essentially two 32-bit values
// stuffed into a 64-bit value. With the code below we assume that all runtime
// calls return 64 bits of result. If they don't, the a1 result register
// contains a bogus value, which is fine because it is caller-saved.
#if V8_TARGET_ARCH_RISCV64
using SimulatorRuntimeCall = ObjectPair (*)(
#elif V8_TARGET_ARCH_RISCV32
using SimulatorRuntimeCall = int64_t (*)(
#endif
    sreg_t arg0, sreg_t arg1, sreg_t arg2, sreg_t arg3, sreg_t arg4,
    sreg_t arg5, sreg_t arg6, sreg_t arg7, sreg_t arg8, sreg_t arg9,
    sreg_t arg10, sreg_t arg11, sreg_t arg12, sreg_t arg13, sreg_t arg14,
    sreg_t arg15, sreg_t arg16, sreg_t arg17, sreg_t arg18, sreg_t arg19);

// These prototypes handle the four types of FP calls.
using SimulatorRuntimeCompareCall = int64_t (*)(double darg0, double darg1);
using SimulatorRuntimeFPFPCall = double (*)(double darg0, double darg1);
using SimulatorRuntimeFPCall = double (*)(double darg0);
using SimulatorRuntimeFPIntCall = double (*)(double darg0, int32_t arg0);

// This signature supports direct call in to API function native callback
// (refer to InvocationCallback in v8.h).
using SimulatorRuntimeDirectApiCall = void (*)(sreg_t arg0);

// This signature supports direct call to accessor getter callback.
using SimulatorRuntimeDirectGetterCall = void (*)(sreg_t arg0, sreg_t arg1);

// Define four args for future flexibility; at the time of this writing only
// one is ever used.
using SimulatorRuntimeFPTaggedCall = double (*)(int64_t arg0, int64_t arg1,
                                                int64_t arg2, int64_t arg3);

#ifdef V8_TARGET_ARCH_RISCV64
using MixedRuntimeCall_0 = AnyCType (*)();
#define BRACKETS(ident, N) ident[N]
#define REP_0(expr, FMT)
#define REP_1(expr, FMT) FMT(expr, 0)
#define REP_2(expr, FMT) REP_1(expr, FMT), FMT(expr, 1)
#define REP_3(expr, FMT) REP_2(expr, FMT), FMT(expr, 2)
#define REP_4(expr, FMT) REP_3(expr, FMT), FMT(expr, 3)
#define REP_5(expr, FMT) REP_4(expr, FMT), FMT(expr, 4)
#define REP_6(expr, FMT) REP_5(expr, FMT), FMT(expr, 5)
#define REP_7(expr, FMT) REP_6(expr, FMT), FMT(expr, 6)
#define REP_8(expr, FMT) REP_7(expr, FMT), FMT(expr, 7)
#define REP_9(expr, FMT) REP_8(expr, FMT), FMT(expr, 8)
#define REP_10(expr, FMT) REP_9(expr, FMT), FMT(expr, 9)
#define REP_11(expr, FMT) REP_10(expr, FMT), FMT(expr, 10)
#define REP_12(expr, FMT) REP_11(expr, FMT), FMT(expr, 11)
#define REP_13(expr, FMT) REP_12(expr, FMT), FMT(expr, 12)
#define REP_14(expr, FMT) REP_13(expr, FMT), FMT(expr, 13)
#define REP_15(expr, FMT) REP_14(expr, FMT), FMT(expr, 14)
#define REP_16(expr, FMT) REP_15(expr, FMT), FMT(expr, 15)
#define REP_17(expr, FMT) REP_16(expr, FMT), FMT(expr, 16)
#define REP_18(expr, FMT) REP_17(expr, FMT), FMT(expr, 17)
#define REP_19(expr, FMT) REP_18(expr, FMT), FMT(expr, 18)
#define REP_20(expr, FMT) REP_19(expr, FMT), FMT(expr, 19)
#define GEN_MAX_PARAM_COUNT(V) \
  V(0)                         \
  V(1)                         \
  V(2)                         \
  V(3)                         \
  V(4)                         \
  V(5)                         \
  V(6)                         \
  V(7)                         \
  V(8)                         \
  V(9)                         \
  V(10)                        \
  V(11)                        \
  V(12)                        \
  V(13)                        \
  V(14)                        \
  V(15)                        \
  V(16)                        \
  V(17)                        \
  V(18)                        \
  V(19)                        \
  V(20)
#define MIXED_RUNTIME_CALL(N) \
  using MixedRuntimeCall_##N = AnyCType (*)(REP_##N(AnyCType arg, CONCAT));
GEN_MAX_PARAM_COUNT(MIXED_RUNTIME_CALL)
#undef MIXED_RUNTIME_CALL
#define CALL_ARGS(N) REP_##N(args, BRACKETS)
#define CALL_TARGET_VARARG(N)                                   \
  if (signature.ParameterCount() == N) { /* NOLINT */           \
    MixedRuntimeCall_##N target =                               \
        reinterpret_cast<MixedRuntimeCall_##N>(target_address); \
    result = target(CALL_ARGS(N));                              \
  } else /* NOLINT */
#define PARAM_REGISTERS a0, a1, a2, a3, a4, a5, a6, a7
#define RETURN_REGISTER a0
#define FP_PARAM_REGISTERS fa0, fa1, fa2, fa3, fa4, fa5, fa6, fa7
#define FP_RETURN_REGISTER fa0
void Simulator::CallAnyCTypeFunction(Address target_address,
                                     const EncodedCSignature& signature) {
  const int64_t* stack_pointer = reinterpret_cast<int64_t*>(get_register(sp));
  const double* double_stack_pointer =
      reinterpret_cast<double*>(get_register(sp));
  const Register kParamRegisters[] = {PARAM_REGISTERS};
  const FPURegister kFPParamRegisters[] = {FP_PARAM_REGISTERS};
  CHECK_LE(signature.ParameterCount(), kMaxCParameters);
  static_assert(sizeof(AnyCType) == 8, "AnyCType is assumed to be 64-bit.");
  AnyCType args[kMaxCParameters];
  int num_gp_params = 0, num_fp_params = 0, num_stack_params = 0;
  for (int i = 0; i < signature.ParameterCount(); ++i) {
    if (signature.IsFloat(i)) {
      if (num_fp_params < 8) {
        args[i].double_value =
            get_fpu_register_double(kFPParamRegisters[num_fp_params++]);
      } else {
        args[i].double_value = double_stack_pointer[num_stack_params++];
      }
    } else {
      if (num_gp_params < 8) {
        args[i].int64_value = get_register(kParamRegisters[num_gp_params++]);
      } else {
        args[i].int64_value = stack_pointer[num_stack_params++];
      }
    }
  }
  AnyCType result;
  GEN_MAX_PARAM_COUNT(CALL_TARGET_VARARG)
  /* else */ {
    UNREACHABLE();
  }
  static_assert(20 == kMaxCParameters,
                "If you've changed kMaxCParameters, please change the "
                "GEN_MAX_PARAM_COUNT macro.");
  if (v8_flags.trace_sim) {
    printf("CallAnyCTypeFunction end result \n");
  }
#undef CALL_TARGET_VARARG
#undef CALL_ARGS
#undef GEN_MAX_PARAM_COUNT
  if (signature.IsReturnFloat()) {
    if (signature.IsReturnFloat64()) {
      set_fpu_register_double(FP_RETURN_REGISTER, result.double_value);
    } else {
      set_fpu_register_float(FP_RETURN_REGISTER, result.float_value);
    }
  } else {
    set_register(RETURN_REGISTER, result.int64_value);
  }
}
#undef PARAM_REGISTERS
#undef RETURN_REGISTER
#undef FP_PARAM_REGISTERS
#undef FP_RETURN_REGISTER
#endif  // V8_TARGET_ARCH_RISCV64

// Software interrupt instructions are used by the simulator to call into the
// C-based V8 runtime. They are also used for debugging with simulator.
void Simulator::SoftwareInterrupt() {
  // There are two instructions that could get us here, the ebreak or ecall
  // instructions are "SYSTEM" class opcode distinuished by Imm12Value field w/
  // the rest of instruction fields being zero
  int32_t func = instr_.Imm12Value();
  // We first check if we met a call_rt_redirected.
  if (instr_.InstructionBits() == rtCallRedirInstr) {  // ECALL
    Redirection* redirection = Redirection::FromInstruction(instr_.instr());

    // This is dodgy but it works because the C entry stubs are never moved.
    int64_t saved_ra = get_register(ra);
    intptr_t external =
        reinterpret_cast<intptr_t>(redirection->external_function());
#ifdef V8_TARGET_ARCH_RISCV64
    Address func_addr =
        reinterpret_cast<Address>(redirection->external_function());
    SimulatorData* simulator_data = isolate_->simulator_data();
    DCHECK_NOT_NULL(simulator_data);
    const EncodedCSignature& signature =
        simulator_data->GetSignatureForTarget(func_addr);
    if (signature.IsValid()) {
      CHECK_EQ(redirection->type(), ExternalReference::FAST_C_CALL);
      CallAnyCTypeFunction(external, signature);
      set_register(ra, saved_ra);
      set_pc(get_register(ra));
      return;
    }
#endif

    sreg_t* stack_pointer = reinterpret_cast<sreg_t*>(get_register(sp));

    const sreg_t arg0 = get_register(a0);
    const sreg_t arg1 = get_register(a1);
    const sreg_t arg2 = get_register(a2);
    const sreg_t arg3 = get_register(a3);
    const sreg_t arg4 = get_register(a4);
    const sreg_t arg5 = get_register(a5);
    const sreg_t arg6 = get_register(a6);
    const sreg_t arg7 = get_register(a7);
    const sreg_t arg8 = stack_pointer[0];
    const sreg_t arg9 = stack_pointer[1];
    const sreg_t arg10 = stack_pointer[2];
    const sreg_t arg11 = stack_pointer[3];
    const sreg_t arg12 = stack_pointer[4];
    const sreg_t arg13 = stack_pointer[5];
    const sreg_t arg14 = stack_pointer[6];
    const sreg_t arg15 = stack_pointer[7];
    const sreg_t arg16 = stack_pointer[8];
    const sreg_t arg17 = stack_pointer[9];
    const sreg_t arg18 = stack_pointer[10];
    const sreg_t arg19 = stack_pointer[11];
    static_assert(kMaxCParameters == 20);

    bool fp_call =
        (redirection->type() == ExternalReference::BUILTIN_FP_FP_CALL) ||
        (redirection->type() == ExternalReference::BUILTIN_COMPARE_CALL) ||
        (redirection->type() == ExternalReference::BUILTIN_FP_CALL) ||
        (redirection->type() == ExternalReference::BUILTIN_FP_INT_CALL);

    sreg_t pc = get_pc();

    if (fp_call) {
      double dval0, dval1;  // one or two double parameters
      int32_t ival;         // zero or one integer parameters
      int64_t iresult = 0;  // integer return value
      double dresult = 0;   // double return value
      GetFpArgs(&dval0, &dval1, &ival);
      SimulatorRuntimeCall generic_target =
          reinterpret_cast<SimulatorRuntimeCall>(external);
      if (v8_flags.trace_sim) {
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_FP_FP_CALL:
          case ExternalReference::BUILTIN_COMPARE_CALL:
            PrintF("Call to host function %s at %p with args %f, %f",
                   ExternalReferenceTable::NameOfIsolateIndependentAddress(
                       pc, IsolateGroup::current()->external_ref_table()),
                   reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                   dval0, dval1);
            break;
          case ExternalReference::BUILTIN_FP_CALL:
            PrintF("Call to host function %s at %p with arg %f",
                   ExternalReferenceTable::NameOfIsolateIndependentAddress(
                       pc, IsolateGroup::current()->external_ref_table()),
                   reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                   dval0);
            break;
          case ExternalReference::BUILTIN_FP_INT_CALL:
            PrintF("Call to host function %s at %p with args %f, %d",
                   ExternalReferenceTable::NameOfIsolateIndependentAddress(
                       pc, IsolateGroup::current()->external_ref_table()),
                   reinterpret_cast<void*>(FUNCTION_ADDR(generic_target)),
                   dval0, ival);
            break;
          default:
            UNREACHABLE();
        }
      }
      switch (redirection->type()) {
        case ExternalReference::BUILTIN_COMPARE_CALL: {
          SimulatorRuntimeCompareCall target =
              reinterpret_cast<SimulatorRuntimeCompareCall>(external);
          iresult = target(dval0, dval1);
          set_register(a0, static_cast<sreg_t>(iresult));
          //  set_register(a1, static_cast<int64_t>(iresult >> 32));
          break;
        }
        case ExternalReference::BUILTIN_FP_FP_CALL: {
          SimulatorRuntimeFPFPCall target =
              reinterpret_cast<SimulatorRuntimeFPFPCall>(external);
          dresult = target(dval0, dval1);
          SetFpResult(dresult);
          break;
        }
        case ExternalReference::BUILTIN_FP_CALL: {
          SimulatorRuntimeFPCall target =
              reinterpret_cast<SimulatorRuntimeFPCall>(external);
          dresult = target(dval0);
          SetFpResult(dresult);
          break;
        }
        case ExternalReference::BUILTIN_FP_INT_CALL: {
          SimulatorRuntimeFPIntCall target =
              reinterpret_cast<SimulatorRuntimeFPIntCall>(external);
          dresult = target(dval0, ival);
          SetFpResult(dresult);
          break;
        }
        default:
          UNREACHABLE();
      }
      if (v8_flags.trace_sim) {
        switch (redirection->type()) {
          case ExternalReference::BUILTIN_COMPARE_CALL:
            PrintF("Returned %08x\n", static_cast<int32_t>(iresult));
            break;
          case ExternalReference::BUILTIN_FP_FP_CALL:
          case ExternalReference::BUILTIN_FP_CALL:
          case ExternalReference::BUILTIN_FP_INT_CALL:
            PrintF("Returned %f\n", dresult);
            break;
          default:
            UNREACHABLE();
        }
      }
    } else if (redirection->type() ==
               ExternalReference::BUILTIN_FP_POINTER_CALL) {
      if (v8_flags.trace_sim) {
        PrintF("Call to host function at %p args %08" REGIx_FORMAT " \n",
               reinterpret_cast<void*>(external), arg0);
      }
      SimulatorRuntimeFPTaggedCall target =
          reinterpret_cast<SimulatorRuntimeFPTaggedCall>(external);
      double dresult = target(arg0, arg1, arg2, arg3);
      SetFpResult(dresult);
      if (v8_flags.trace_sim) {
        PrintF("Returned %f\n", dresult);
      }
    } else if (redirection->type() == ExternalReference::DIRECT_API_CALL) {
      // See callers of MacroAssembler::CallApiFunctionAndReturn for
      // explanation of register usage.
      // void f(v8::FunctionCallbackInfo&)
      if (v8_flags.trace_sim) {
        PrintF("Call to host function %s at %p args %08" REGIx_FORMAT " \n",
               ExternalReferenceTable::NameOfIsolateIndependentAddress(
                   pc, IsolateGroup::current()->external_ref_table()),
               reinterpret_cast<void*>(external), arg0);
      }
      SimulatorRuntimeDirectApiCall target =
          reinterpret_cast<SimulatorRuntimeDirectApiCall>(external);
      target(arg0);
    } else if (redirection->type() == ExternalReference::DIRECT_GETTER_CALL) {
      // See callers of MacroAssembler::CallApiFunctionAndReturn for
      // explanation of register usage.
      // void f(v8::Local<String> property, v8::PropertyCallbackInfo& info)
      if (v8_flags.trace_sim) {
        PrintF("Call to host function at %p args %08" REGIx_FORMAT
               "  %08" REGIx_FORMAT " \n",
               reinterpret_cast<void*>(external), arg0, arg1);
      }
      SimulatorRuntimeDirectGetterCall target =
          reinterpret_cast<SimulatorRuntimeDirectGetterCall>(external);
      target(arg0, arg1);
    } else {
#ifdef V8_TARGET_ARCH_RISCV64
      DCHECK(redirection->type() == ExternalReference::BUILTIN_CALL ||
             redirection->type() == ExternalReference::BUILTIN_CALL_PAIR);
#else   // V8_TARGET_ARCH_RISCV32
        //  FAST_C_CALL is temporarily handled here as well, because we lack
        //  proper support for direct C calls with FP params in the simulator.
        //  The generic BUILTIN_CALL path assumes all parameters are passed in
        //  the GP registers, thus supporting calling the slow callback without
        //  crashing. The reason for that is that in the mjsunit tests we check
        //  the `fast_c_api.supports_fp_params` (which is false on non-simulator
        //  builds for arm/arm64), thus we expect that the slow path will be
        //  called. And since the slow path passes the arguments as a `const
        //  FunctionCallbackInfo<Value>&` (which is a GP argument), the call is
        //  made correctly.
      DCHECK(redirection->type() == ExternalReference::BUILTIN_CALL ||
             redirection->type() == ExternalReference::BUILTIN_CALL_PAIR ||
             redirection->type() == ExternalReference::FAST_C_CALL);
#endif  // V8_TARGET_ARCH_RISCV64
      SimulatorRuntimeCall target =
          reinterpret_cast<SimulatorRuntimeCall>(external);
      if (v8_flags.trace_sim) {
        PrintF(
            "Call to host function %s at %p "
            "args %08" REGIx_FORMAT " , %08" REGIx_FORMAT " , %08" REGIx_FORMAT
            " , %08" REGIx_FORMAT " , %08" REGIx_FORMAT " , %08" REGIx_FORMAT
            " , %08" REGIx_FORMAT " , %08" REGIx_FORMAT " , %08" REGIx_FORMAT
            " , %08" REGIx_FORMAT " , %016" REGIx_FORMAT " , %016" REGIx_FORMAT
            " , %016" REGIx_FORMAT " , %016" REGIx_FORMAT " , %016" REGIx_FORMAT
            " , %016" REGIx_FORMAT " , %016" REGIx_FORMAT " , %016" REGIx_FORMAT
            " , %016" REGIx_FORMAT " , %016" REGIx_FORMAT " \n",
            ExternalReferenceTable::NameOfIsolateIndependentAddress(
                pc, IsolateGroup::current()->external_ref_table()),
            reinterpret_cast<void*>(FUNCTION_ADDR(target)), arg0, arg1, arg2,
            arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
            arg13, arg14, arg15, arg16, arg17, arg18, arg19);
      }
#if V8_TARGET_ARCH_RISCV64
      ObjectPair result = target(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                                 arg8, arg9, arg10, arg11, arg12, arg13, arg14,
                                 arg15, arg16, arg17, arg18, arg19);
      set_register(a0, (sreg_t)(result.x));
      set_register(a1, (sreg_t)(result.y));

#elif V8_TARGET_ARCH_RISCV32
      int64_t result = target(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                              arg8, arg9, arg10, arg11, arg12, arg13, arg14,
                              arg15, arg16, arg17, arg18, arg19);
      set_register(a0, (sreg_t)result);
      set_register(a1, (sreg_t)(result >> 32));
#endif
    }
    if (v8_flags.trace_sim) {
      PrintF("Returned %08" REGIx_FORMAT "  : %08" REGIx_FORMAT " \n",
             get_register(a1), get_register(a0));
    }
    set_register(ra, saved_ra);
    set_pc(get_register(ra));

  } else if (func == 1) {  // EBREAK
    int32_t code = get_ebreak_code(instr_.instr());
    set_pc(get_pc() + kInstrSize * 2);
    if (code != -1 && static_cast<uint32_t>(code) <= kMaxStopCode) {
      if (IsWatchpoint(code)) {
        PrintWatchpoint(code);
      } else if (IsTracepoint(code)) {
        if (!v8_flags.debug_sim) {
          PrintF("Add --debug-sim when tracepoint instruction is used.\n");
          abort();
        }
        Builtin builtin = LookUp((Address)get_pc());
        printf("%d %d %d %d\n", code, code & LOG_TRACE, code & LOG_REGS,
               code & kDebuggerTracingDirectivesMask);
        if (builtin != Builtin::kNoBuiltinId) {
          printf("Builitin: %s\n", builtins_.name(builtin));
        }
        switch (code & kDebuggerTracingDirectivesMask) {
          case TRACE_ENABLE:
            if (code & LOG_TRACE) {
              v8_flags.trace_sim = true;
            }
            if (code & LOG_REGS) {
              RiscvDebugger dbg(this);
              dbg.PrintAllRegs();
            }
            break;
          case TRACE_DISABLE:
            if (code & LOG_TRACE) {
              v8_flags.trace_sim = false;
            }
            break;
          default:
            UNREACHABLE();
        }
      } else {
        IncreaseStopCounter(code);
        HandleStop(code);
      }
    } else if (IsSwitchStackLimit(code)) {
      DoSwitchStackLimit(instr_.instr());
    } else {
      // All remaining break_ codes, and all traps are handled here.
      RiscvDebugger dbg(this);
      dbg.Debug();
    }
  } else {
    UNREACHABLE();
  }
}

// Stop helper functions.
bool Simulator::IsWatchpoint(reg_t code) {
  return (code <= kMaxWatchpointCode);
}

bool Simulator::IsTracepoint(reg_t code) {
  return (code <= kMaxTracepointCode && code > kMaxWatchpointCode);
}

bool Simulator::IsSwitchStackLimit(reg_t code) {
  return code == kExceptionIsSwitchStackLimit;
}

void Simulator::PrintWatchpoint(reg_t code) {
  RiscvDebugger dbg(this);
  ++break_count_;
  PrintF("\n---- watchpoint %" REGId_FORMAT
         "  marker: %3d  (instr count: %8" PRId64
         " ) ----------"
         "----------------------------------",
         code, break_count_, icount_);
  dbg.PrintAllRegs();  // Print registers and continue running.
}

void Simulator::HandleStop(reg_t code) {
  // Stop if it is enabled, otherwise go on jumping over the stop
  // and the message address.
  if (IsEnabledStop(code)) {
    PrintF("Simulator hit stop (%" REGId_FORMAT ")\n", code);
    DieOrDebug();
  }
}

bool Simulator::IsStopInstruction(Instruction* instr) {
  if (instr->InstructionBits() != kBreakInstr) return false;
  int32_t code = get_ebreak_code(instr);
  return code != -1 && static_cast<uint32_t>(code) > kMaxWatchpointCode &&
         static_cast<uint32_t>(code) <= kMaxStopCode;
}

bool Simulator::IsEnabledStop(reg_t code) {
  DCHECK_LE(code, kMaxStopCode);
  DCHECK_GT(code, kMaxWatchpointCode);
  return !(watched_stops_[code].count & kStopDisabledBit);
}

void Simulator::EnableStop(reg_t code) {
  if (!IsEnabledStop(code)) {
    watched_stops_[code].count &= ~kStopDisabledBit;
  }
}

void Simulator::DisableStop(reg_t code) {
  if (IsEnabledStop(code)) {
    watched_stops_[code].count |= kStopDisabledBit;
  }
}

void Simulator::IncreaseStopCounter(reg_t code) {
  DCHECK_LE(code, kMaxStopCode);
  if ((watched_stops_[code].count & ~(1 << 31)) == 0x7FFFFFFF) {
    PrintF("Stop counter for code %" REGId_FORMAT
           "  has overflowed.\n"
           "Enabling this code and reseting the counter to 0.\n",
           code);
    watched_stops_[code].count = 0;
    EnableStop(code);
  } else {
    watched_stops_[code].count++;
  }
}

// Print a stop status.
void Simulator::PrintStopInfo(reg_t code) {
  if (code <= kMaxWatchpointCode) {
    PrintF("That is a watchpoint, not a stop.\n");
    return;
  } else if (code > kMaxStopCode) {
    PrintF("Code too large, only %u stops can be used\n", kMaxStopCode + 1);
    return;
  }
  const char* state = IsEnabledStop(code) ? "Enabled" : "Disabled";
  int32_t count = watched_stops_[code].count & ~kStopDisabledBit;
  // Don't print the state of unused breakpoints.
  if (count != 0) {
    if (watched_stops_[code].desc) {
      PrintF("stop %" REGId_FORMAT "  - 0x%" REGIx_FORMAT
             " : \t%s, \tcounter = %i, \t%s\n",
             code, code, state, count, watched_stops_[code].desc);
    } else {
      PrintF("stop %" REGId_FORMAT "  - 0x%" REGIx_FORMAT
             " : \t%s, \tcounter = %i\n",
             code, code, state, count);
    }
  }
}

void Simulator::SignalException(Exception e) {
  FATAL("Error: Exception %i raised.", static_cast<int>(e));
}

// RISCV Instruction Decode Routine
void Simulator::DecodeRVRType() {
  switch (instr_.InstructionBits() & kRTypeMask) {
    case RO_ADD: {
      set_rd(sext_xlen(rs1() + rs2()));
      break;
    }
    case RO_SUB: {
      set_rd(sext_xlen(rs1() - rs2()));
      break;
    }
    case RO_SLL: {
      set_rd(sext_xlen(rs1() << (rs2() & (xlen - 1))));
      break;
    }
    case RO_SLT: {
      set_rd(sreg_t(rs1()) < sreg_t(rs2()));
      break;
    }
    case RO_SLTU: {
      set_rd(reg_t(rs1()) < reg_t(rs2()));
      break;
    }
    case RO_XOR: {
      set_rd(rs1() ^ rs2());
      break;
    }
    case RO_SRL: {
      set_rd(sext_xlen(zext_xlen(rs1()) >> (rs2() & (xlen - 1))));
      break;
    }
    case RO_SRA: {
      set_rd(sext_xlen(sext_xlen(rs1()) >> (rs2() & (xlen - 1))));
      break;
    }
    case RO_OR: {
      set_rd(rs1() | rs2());
      break;
    }
    case RO_AND: {
      set_rd(rs1() & rs2());
      break;
    }
    case RO_ANDN:
      set_rd(rs1() & ~rs2());
      break;
    case RO_ORN:
      set_rd(rs1() | (~rs2()));
      break;
    case RO_XNOR:
      set_rd((~rs1()) ^ (~rs2()));
      break;
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_ADDW: {
      set_rd(sext32(rs1() + rs2()));
      break;
    }
    case RO_ADDUW:
      set_rd(zext32(rs1()) + rs2());
      break;
    case RO_SUBW: {
      set_rd(sext32(rs1() - rs2()));
      break;
    }
    case RO_SLLW: {
      set_rd(sext32(rs1() << (rs2() & 0x1F)));
      break;
    }
    case RO_SRLW: {
      set_rd(sext32(uint32_t(rs1()) >> (rs2() & 0x1F)));
      break;
    }
    case RO_SRAW: {
      set_rd(sext32(int32_t(rs1()) >> (rs2() & 0x1F)));
      break;
    }
    case RO_SH1ADDUW: {
      set_rd(rs2() + (zext32(rs1()) << 1));
      break;
    }
    case RO_SH2ADDUW: {
      set_rd(rs2() + (zext32(rs1()) << 2));
      break;
    }
    case RO_SH3ADDUW: {
      set_rd(rs2() + (zext32(rs1()) << 3));
      break;
    }
    case RO_ROLW: {
      reg_t extz_rs1 = zext32(rs1());
      sreg_t shamt = rs2() & 31;
      set_rd(sext32((extz_rs1 << shamt) | (extz_rs1 >> (32 - shamt))));
      break;
    }
    case RO_RORW: {
      reg_t extz_rs1 = zext32(rs1());
      sreg_t shamt = rs2() & 31;
      set_rd(sext32((extz_rs1 >> shamt) | (extz_rs1 << (32 - shamt))));
      break;
    }
#endif /* V8_TARGET_ARCH_RISCV64 */
      // TODO(riscv): Add RISCV M extension macro
    case RO_MUL: {
      set_rd(rs1() * rs2());
      break;
    }
    case RO_MULH: {
      set_rd(mulh(rs1(), rs2()));
      break;
    }
    case RO_MULHSU: {
      set_rd(mulhsu(rs1(), rs2()));
      break;
    }
    case RO_MULHU: {
      set_rd(mulhu(rs1(), rs2()));
      break;
    }
    case RO_DIV: {
      sreg_t lhs = sext_xlen(rs1());
      sreg_t rhs = sext_xlen(rs2());
      if (rhs == 0) {
        set_rd(-1);
      } else if (lhs == INTPTR_MIN && rhs == -1) {
        set_rd(lhs);
      } else {
        set_rd(sext_xlen(lhs / rhs));
      }
      break;
    }
    case RO_DIVU: {
      reg_t lhs = zext_xlen(rs1());
      reg_t rhs = zext_xlen(rs2());
      if (rhs == 0) {
        set_rd(UINTPTR_MAX);
      } else {
        set_rd(zext_xlen(lhs / rhs));
      }
      break;
    }
    case RO_REM: {
      sreg_t lhs = sext_xlen(rs1());
      sreg_t rhs = sext_xlen(rs2());
      if (rhs == 0) {
        set_rd(lhs);
      } else if (lhs == INTPTR_MIN && rhs == -1) {
        set_rd(0);
      } else {
        set_rd(sext_xlen(lhs % rhs));
      }
      break;
    }
    case RO_REMU: {
      reg_t lhs = zext_xlen(rs1());
      reg_t rhs = zext_xlen(rs2());
      if (rhs == 0) {
        set_rd(lhs);
      } else {
        set_rd(zext_xlen(lhs % rhs));
      }
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_MULW: {
      set_rd(sext32(sext32(rs1()) * sext32(rs2())));
      break;
    }
    case RO_DIVW: {
      sreg_t lhs = sext32(rs1());
      sreg_t rhs = sext32(rs2());
      if (rhs == 0) {
        set_rd(-1);
      } else if (lhs == INT32_MIN && rhs == -1) {
        set_rd(lhs);
      } else {
        set_rd(sext32(lhs / rhs));
      }
      break;
    }
    case RO_DIVUW: {
      reg_t lhs = zext32(rs1());
      reg_t rhs = zext32(rs2());
      if (rhs == 0) {
        set_rd(UINT32_MAX);
      } else {
        set_rd(zext32(lhs / rhs));
      }
      break;
    }
    case RO_REMW: {
      sreg_t lhs = sext32(rs1());
      sreg_t rhs = sext32(rs2());
      if (rhs == 0) {
        set_rd(lhs);
      } else if (lhs == INT32_MIN && rhs == -1) {
        set_rd(0);
      } else {
        set_rd(sext32(lhs % rhs));
      }
      break;
    }
    case RO_REMUW: {
      reg_t lhs = zext32(rs1());
      reg_t rhs = zext32(rs2());
      if (rhs == 0) {
        set_rd(zext32(lhs));
      } else {
        set_rd(zext32(lhs % rhs));
      }
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    case RO_SH1ADD:
      set_rd(rs2() + (rs1() << 1));
      break;
    case RO_SH2ADD:
      set_rd(rs2() + (rs1() << 2));
      break;
    case RO_SH3ADD:
      set_rd(rs2() + (rs1() << 3));
      break;
    case RO_MAX:
      set_rd(rs1() < rs2() ? rs2() : rs1());
      break;
    case RO_MAXU:
      set_rd(reg_t(rs1()) < reg_t(rs2()) ? rs2() : rs1());
      break;
    case RO_MIN:
      set_rd(rs1() < rs2() ? rs1() : rs2());
      break;
    case RO_MINU:
      set_rd(reg_t(rs1()) < reg_t(rs2()) ? rs1() : rs2());
      break;
    case RO_ZEXTH:
      set_rd(zext_xlen(uint16_t(rs1())));
      break;
    case RO_ROL: {
      sreg_t shamt = rs2() & (xlen - 1);
      set_rd((reg_t(rs1()) << shamt) | (reg_t(rs1()) >> (xlen - shamt)));
      break;
    }
    case RO_ROR: {
      sreg_t shamt = rs2() & (xlen - 1);
      set_rd((reg_t(rs1()) >> shamt) | (reg_t(rs1()) << (xlen - shamt)));
      break;
    }
    case RO_BCLR: {
      sreg_t index = rs2() & (xlen - 1);
      set_rd(rs1() & ~(1l << index));
      break;
    }
    case RO_BEXT: {
      sreg_t index = rs2() & (xlen - 1);
      set_rd((rs1() >> index) & 1);
      break;
    }
    case RO_BINV: {
      sreg_t index = rs2() & (xlen - 1);
      set_rd(rs1() ^ (1 << index));
      break;
    }
    case RO_BSET: {
      sreg_t index = rs2() & (xlen - 1);
      set_rd(rs1() | (1 << index));
      break;
    }
    case RO_CZERO_EQZ: {
      sreg_t condition = rs2();
      set_rd(condition == 0 ? 0 : rs1());
      break;
    }
    case RO_CZERO_NEZ: {
      sreg_t condition = rs2();
      set_rd(condition != 0 ? 0 : rs1());
      break;
    }
    default: {
      switch (instr_.BaseOpcode()) {
        case AMO:
          DecodeRVRAType();
          break;
        case OP_FP:
          DecodeRVRFPType();
          break;
        default:
          UNSUPPORTED();
      }
    }
  }
}

float Simulator::RoundF2FHelper(float input_val, int rmode) {
  if (rmode == DYN) rmode = get_dynamic_rounding_mode();

  float rounded = 0;
  switch (rmode) {
    case RNE: {  // Round to Nearest, tiest to Even
      rounded = floorf(input_val);
      float error = input_val - rounded;

      // Take care of correctly handling the range [-0.5, -0.0], which must
      // yield -0.0.
      if ((-0.5 <= input_val) && (input_val < 0.0)) {
        rounded = -0.0;

        // If the error is greater than 0.5, or is equal to 0.5 and the integer
        // result is odd, round up.
      } else if ((error > 0.5) ||
                 ((error == 0.5) && (std::fmod(rounded, 2) != 0))) {
        rounded++;
      }
      break;
    }
    case RTZ:  // Round towards Zero
      rounded = std::truncf(input_val);
      break;
    case RDN:  // Round Down (towards -infinity)
      rounded = floorf(input_val);
      break;
    case RUP:  // Round Up (towards +infinity)
      rounded = ceilf(input_val);
      break;
    case RMM:  // Round to Nearest, tiest to Max Magnitude
      rounded = std::roundf(input_val);
      break;
    default:
      UNREACHABLE();
  }

  return rounded;
}

double Simulator::RoundF2FHelper(double input_val, int rmode) {
  if (rmode == DYN) rmode = get_dynamic_rounding_mode();

  double rounded = 0;
  switch (rmode) {
    case RNE: {  // Round to Nearest, tiest to Even
      rounded = std::floor(input_val);
      double error = input_val - rounded;

      // Take care of correctly handling the range [-0.5, -0.0], which must
      // yield -0.0.
      if ((-0.5 <= input_val) && (input_val < 0.0)) {
        rounded = -0.0;

        // If the error is greater than 0.5, or is equal to 0.5 and the integer
        // result is odd, round up.
      } else if ((error > 0.5) ||
                 ((error == 0.5) && (std::fmod(rounded, 2) != 0))) {
        rounded++;
      }
      break;
    }
    case RTZ:  // Round towards Zero
      rounded = std::trunc(input_val);
      break;
    case RDN:  // Round Down (towards -infinity)
      rounded = std::floor(input_val);
      break;
    case RUP:  // Round Up (towards +infinity)
      rounded = std::ceil(input_val);
      break;
    case RMM:  // Round to Nearest, tiest to Max Magnitude
      rounded = std::round(input_val);
      break;
    default:
      UNREACHABLE();
  }
  return rounded;
}

// convert rounded floating-point to integer types, handle input values that
// are out-of-range, underflow, or NaN, and set appropriate fflags
template <typename I_TYPE, typename F_TYPE>
I_TYPE Simulator::RoundF2IHelper(F_TYPE original, int rmode) {
  DCHECK(std::is_integral<I_TYPE>::value);

  DCHECK((std::is_same<F_TYPE, float>::value ||
          std::is_same<F_TYPE, double>::value));

  I_TYPE max_i = std::numeric_limits<I_TYPE>::max();
  I_TYPE min_i = std::numeric_limits<I_TYPE>::min();

  if (!std::isfinite(original)) {
    set_fflags(kInvalidOperation);
    if (std::isnan(original) ||
        original == std::numeric_limits<F_TYPE>::infinity()) {
      return max_i;
    } else {
      DCHECK(original == -std::numeric_limits<F_TYPE>::infinity());
      return min_i;
    }
  }

  F_TYPE rounded = RoundF2FHelper(original, rmode);
  if (original != rounded) set_fflags(kInexact);

  if (!std::isfinite(rounded)) {
    set_fflags(kInvalidOperation);
    if (std::isnan(rounded) ||
        rounded == std::numeric_limits<F_TYPE>::infinity()) {
      return max_i;
    } else {
      DCHECK(rounded == -std::numeric_limits<F_TYPE>::infinity());
      return min_i;
    }
  }

  // Since integer max values are either all 1s (for unsigned) or all 1s
  // except for sign-bit (for signed), they cannot be represented precisely in
  // floating point, in order to precisely tell whether the rounded floating
  // point is within the max range, we compare against (max_i+1) which would
  // have a single 1 w/ many trailing zeros
  float max_i_plus_1 =
      std::is_same<uint64_t, I_TYPE>::value
          ? 0x1p64f  // uint64_t::max + 1 cannot be represented in integers,
                     // so use its float representation directly
          : static_cast<float>(static_cast<uint64_t>(max_i) + 1);
  if (rounded >= max_i_plus_1) {
    set_fflags(kFPUOverflow | kInvalidOperation);
    return max_i;
  }

  // Since min_i (either 0 for unsigned, or for signed) is represented
  // precisely in floating-point,  comparing rounded directly against min_i
  if (rounded <= min_i) {
    if (rounded < min_i) set_fflags(kFPUOverflow | kInvalidOperation);
    return min_i;
  }

  F_TYPE underflow_fval =
      std::is_same<F_TYPE, float>::value ? FLT_MIN : DBL_MIN;
  if (rounded < underflow_fval && rounded > -underflow_fval && rounded != 0) {
    set_fflags(kUnderflow);
  }

  return static_cast<I_TYPE>(rounded);
}

template <typename T>
static int64_t FclassHelper(T value) {
  switch (std::fpclassify(value)) {
    case FP_INFINITE:
      return (std::signbit(value) ? kNegativeInfinity : kPositiveInfinity);
    case FP_NAN:
      return (isSnan(value) ? kSignalingNaN : kQuietNaN);
    case FP_NORMAL:
      return (std::signbit(value) ? kNegativeNormalNumber
                                  : kPositiveNormalNumber);
    case FP_SUBNORMAL:
      return (std::signbit(value) ? kNegativeSubnormalNumber
                                  : kPositiveSubnormalNumber);
    case FP_ZERO:
      return (std::signbit(value) ? kNegativeZero : kPositiveZero);
    default:
      UNREACHABLE();
  }
}

template <typename T>
bool Simulator::CompareFHelper(T input1, T input2, FPUCondition cc) {
  DCHECK(std::is_floating_point<T>::value);
  bool result = false;
  switch (cc) {
    case LT:
    case LE:
      // FLT, FLE are signaling compares
      if (std::isnan(input1) || std::isnan(input2)) {
        set_fflags(kInvalidOperation);
        result = false;
      } else {
        result = (cc == LT) ? (input1 < input2) : (input1 <= input2);
      }
      break;

    case EQ:
      if (std::numeric_limits<T>::signaling_NaN() == input1 ||
          std::numeric_limits<T>::signaling_NaN() == input2) {
        set_fflags(kInvalidOperation);
      }
      if (std::isnan(input1) || std::isnan(input2)) {
        result = false;
      } else {
        result = (input1 == input2);
      }
      break;
    case NE:
      if (std::numeric_limits<T>::signaling_NaN() == input1 ||
          std::numeric_limits<T>::signaling_NaN() == input2) {
        set_fflags(kInvalidOperation);
      }
      if (std::isnan(input1) || std::isnan(input2)) {
        result = true;
      } else {
        result = (input1 != input2);
      }
      break;
    default:
      UNREACHABLE();
  }
  return result;
}

template <typename T>
static inline bool is_invalid_fmul(T src1, T src2) {
  return (isinf(src1) && src2 == static_cast<T>(0.0)) ||
         (src1 == static_cast<T>(0.0) && isinf(src2));
}

template <typename T>
static inline bool is_invalid_fadd(T src1, T src2) {
  return (isinf(src1) && isinf(src2) &&
          std::signbit(src1) != std::signbit(src2));
}

template <typename T>
static inline bool is_invalid_fsub(T src1, T src2) {
  return (isinf(src1) && isinf(src2) &&
          std::signbit(src1) == std::signbit(src2));
}

template <typename T>
static inline bool is_invalid_fdiv(T src1, T src2) {
  return ((src1 == 0 && src2 == 0) || (isinf(src1) && isinf(src2)));
}

template <typename T>
static inline bool is_invalid_fsqrt(T src1) {
  return (src1 < 0);
}

void Simulator::DecodeRVRAType() {
  // TODO(riscv): Add macro for RISCV A extension
  // Special handling for A extension instructions because it uses func5
  // For all A extension instruction, V8 simulator is pure sequential. No
  // Memory address lock or other synchronizaiton behaviors.
  switch (instr_.InstructionBits() & kRATypeMask) {
    case RO_LR_W: {
      sreg_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      {
        base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
        if ((addr & 0x3) != 0) {
          DieOrDebug();
        }
        auto val = ReadMem<int32_t>(addr, instr_.instr());
        set_rd(sext32(val), false);
        TraceMemRd(addr, val, get_register(rd_reg()));
        local_monitor_.NotifyLoadLinked(addr, TransactionSize::Word);
        GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                      &global_monitor_thread_);
      }
      break;
    }
    case RO_SC_W: {
      sreg_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int32_t))) return;
      if ((addr & 0x3) != 0) {
        DieOrDebug();
      }
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      if (local_monitor_.NotifyStoreConditional(addr, TransactionSize::Word) &&
          GlobalMonitor::Get()->NotifyStoreConditional_Locked(
              addr, &global_monitor_thread_)) {
        local_monitor_.NotifyStore();
        GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
        WriteMem<int32_t>(rs1(), (int32_t)rs2(), instr_.instr());
        set_rd(0, false);
      } else {
        set_rd(1, false);
      }
      break;
    }
    case RO_AMOSWAP_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return (uint32_t)rs2(); }, instr_.instr(),
          WORD)));
      break;
    }
    case RO_AMOADD_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs + (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOXOR_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs ^ (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOAND_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs & (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOOR_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return lhs | (uint32_t)rs2(); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMIN_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<int32_t>(
          rs1(), [&](int32_t lhs) { return std::min(lhs, (int32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMAX_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<int32_t>(
          rs1(), [&](int32_t lhs) { return std::max(lhs, (int32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMINU_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return std::min(lhs, (uint32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
    case RO_AMOMAXU_W: {
      if ((rs1() & 0x3) != 0) {
        DieOrDebug();
      }
      set_rd(sext32(amo<uint32_t>(
          rs1(), [&](uint32_t lhs) { return std::max(lhs, (uint32_t)rs2()); },
          instr_.instr(), WORD)));
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_LR_D: {
      int64_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      {
        base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
        auto val = ReadMem<int64_t>(addr, instr_.instr());
        set_rd(val, false);
        TraceMemRd(addr, val, get_register(rd_reg()));
        local_monitor_.NotifyLoadLinked(addr, TransactionSize::DoubleWord);
        GlobalMonitor::Get()->NotifyLoadLinked_Locked(addr,
                                                      &global_monitor_thread_);
        break;
      }
    }
    case RO_SC_D: {
      int64_t addr = rs1();
      if (!ProbeMemory(addr, sizeof(int64_t))) return;
      base::MutexGuard lock_guard(&GlobalMonitor::Get()->mutex);
      if (local_monitor_.NotifyStoreConditional(addr,
                                                TransactionSize::DoubleWord) &&
          (GlobalMonitor::Get()->NotifyStoreConditional_Locked(
              addr, &global_monitor_thread_))) {
        GlobalMonitor::Get()->NotifyStore_Locked(&global_monitor_thread_);
        WriteMem<int64_t>(rs1(), rs2(), instr_.instr());
        set_rd(0, false);
      } else {
        set_rd(1, false);
      }
      break;
    }
    case RO_AMOSWAP_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return rs2(); }, instr_.instr(), DWORD));
      break;
    }
    case RO_AMOADD_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs + rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOXOR_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs ^ rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOAND_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs & rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOOR_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return lhs | rs2(); }, instr_.instr(),
          DWORD));
      break;
    }
    case RO_AMOMIN_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return std::min(lhs, rs2()); },
          instr_.instr(), DWORD));
      break;
    }
    case RO_AMOMAX_D: {
      set_rd(amo<int64_t>(
          rs1(), [&](int64_t lhs) { return std::max(lhs, rs2()); },
          instr_.instr(), DWORD));
      break;
    }
    case RO_AMOMINU_D: {
      set_rd(amo<uint64_t>(
          rs1(), [&](uint64_t lhs) { return std::min(lhs, (uint64_t)rs2()); },
          instr_.instr(), DWORD));
      break;
    }
    case RO_AMOMAXU_D: {
      set_rd(amo<uint64_t>(
          rs1(), [&](uint64_t lhs) { return std::max(lhs, (uint64_t)rs2()); },
          instr_.instr(), DWORD));
      break;
    }
#endif /*V8_TARGET_ARCH_RISCV64*/
    // TODO(riscv): End Add macro for RISCV A extension
    default: {
      UNSUPPORTED();
    }
  }
}

void Simulator::DecodeRVRFPType() {
  // OP_FP instructions (F/D) uses func7 first. Some further uses func3 and
  // rs2()

  // kRATypeMask is only for func7
  switch (instr_.InstructionBits() & kRFPTypeMask) {
    // TODO(riscv): Add macro for RISCV F extension
    case RO_FADD_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fadd(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return frs1 + frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FSUB_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fsub(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return frs1 - frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FMUL_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fmul(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return frs1 * frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FDIV_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2) {
        if (is_invalid_fdiv(frs1, frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else if (frs2 == 0.0f) {
          this->set_fflags(kDivideByZero);
          return (std::signbit(frs1) == std::signbit(frs2)
                      ? std::numeric_limits<float>::infinity()
                      : -std::numeric_limits<float>::infinity());
        } else {
          return frs1 / frs2;
        }
      };
      set_frd(CanonicalizeFPUOp2<float>(fn));
      break;
    }
    case RO_FSQRT_S: {
      if (instr_.Rs2Value() == 0b00000) {
        // TODO(riscv): use rm value (round mode)
        auto fn = [this](float frs) {
          if (is_invalid_fsqrt(frs)) {
            this->set_fflags(kInvalidOperation);
            return std::numeric_limits<float>::quiet_NaN();
          } else {
            return std::sqrt(frs);
          }
        };
        set_frd(CanonicalizeFPUOp1<float>(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FSGNJ_S: {  // RO_FSGNJN_S  RO_FSQNJX_S
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FSGNJ_S
          set_frd(fsgnj32(frs1_boxed(), frs2_boxed(), false, false));
          break;
        }
        case 0b001: {  // RO_FSGNJN_S
          set_frd(fsgnj32(frs1_boxed(), frs2_boxed(), true, false));
          break;
        }
        case 0b010: {  // RO_FSQNJX_S
          set_frd(fsgnj32(frs1_boxed(), frs2_boxed(), false, true));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMIN_S: {  // RO_FMAX_S
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FMIN_S
          set_frd(FMaxMinHelper(frs1(), frs2(), MaxMinKind::kMin));
          break;
        }
        case 0b001: {  // RO_FMAX_S
          set_frd(FMaxMinHelper(frs1(), frs2(), MaxMinKind::kMax));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_W_S: {  // RO_FCVT_WU_S , 64F RO_FCVT_L_S RO_FCVT_LU_S
      float original_val = frs1();
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_W_S
          set_rd(RoundF2IHelper<int32_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00001: {  // RO_FCVT_WU_S
          set_rd(sext32(
              RoundF2IHelper<uint32_t>(original_val, instr_.RoundMode())));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_L_S
          set_rd(RoundF2IHelper<int64_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00011: {  // RO_FCVT_LU_S
          set_rd(RoundF2IHelper<uint64_t>(original_val, instr_.RoundMode()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMV: {  // RO_FCLASS_S
      switch (instr_.Funct3Value()) {
        case 0b000: {
          if (instr_.Rs2Value() == 0b00000) {
            // RO_FMV_X_W
            set_rd(sext32(get_fpu_register_word(rs1_reg())));
          } else {
            UNSUPPORTED();
          }
          break;
        }
        case 0b001: {  // RO_FCLASS_S
          set_rd(FclassHelper(frs1()));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FLE_S: {  // RO_FEQ_S RO_FLT_S RO_FLE_S
      switch (instr_.Funct3Value()) {
        case 0b010: {  // RO_FEQ_S
          set_rd(CompareFHelper(frs1(), frs2(), EQ));
          break;
        }
        case 0b001: {  // RO_FLT_S
          set_rd(CompareFHelper(frs1(), frs2(), LT));
          break;
        }
        case 0b000: {  // RO_FLE_S
          set_rd(CompareFHelper(frs1(), frs2(), LE));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_S_W: {  // RO_FCVT_S_WU , 64F RO_FCVT_S_L RO_FCVT_S_LU
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_S_W
          set_frd(static_cast<float>((int32_t)rs1()));
          break;
        }
        case 0b00001: {  // RO_FCVT_S_WU
          set_frd(static_cast<float>((uint32_t)rs1()));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_S_L
          set_frd(static_cast<float>((int64_t)rs1()));
          break;
        }
        case 0b00011: {  // RO_FCVT_S_LU
          set_frd(static_cast<float>((uint64_t)rs1()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMV_W_X: {
      if (instr_.Funct3Value() == 0b000) {
        // since FMV preserves source bit-pattern, no need to canonize
        Float32 result = Float32::FromBits((uint32_t)rs1());
        set_frd(result);
      } else {
        UNSUPPORTED();
      }
      break;
    }
      // TODO(riscv): Add macro for RISCV D extension
    case RO_FADD_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fadd(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return drs1 + drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FSUB_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fsub(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return drs1 - drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FMUL_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fmul(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return drs1 * drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FDIV_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2) {
        if (is_invalid_fdiv(drs1, drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else if (drs2 == 0.0) {
          this->set_fflags(kDivideByZero);
          return (std::signbit(drs1) == std::signbit(drs2)
                      ? std::numeric_limits<double>::infinity()
                      : -std::numeric_limits<double>::infinity());
        } else {
          return drs1 / drs2;
        }
      };
      set_drd(CanonicalizeFPUOp2<double>(fn));
      break;
    }
    case RO_FSQRT_D: {
      if (instr_.Rs2Value() == 0b00000) {
        // TODO(riscv): use rm value (round mode)
        auto fn = [this](double drs) {
          if (is_invalid_fsqrt(drs)) {
            this->set_fflags(kInvalidOperation);
            return std::numeric_limits<double>::quiet_NaN();
          } else {
            return std::sqrt(drs);
          }
        };
        set_drd(CanonicalizeFPUOp1<double>(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FSGNJ_D: {  // RO_FSGNJN_D RO_FSQNJX_D
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FSGNJ_D
          set_drd(fsgnj64(drs1_boxed(), drs2_boxed(), false, false));
          break;
        }
        case 0b001: {  // RO_FSGNJN_D
          set_drd(fsgnj64(drs1_boxed(), drs2_boxed(), true, false));
          break;
        }
        case 0b010: {  // RO_FSQNJX_D
          set_drd(fsgnj64(drs1_boxed(), drs2_boxed(), false, true));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FMIN_D: {  // RO_FMAX_D
      switch (instr_.Funct3Value()) {
        case 0b000: {  // RO_FMIN_D
          set_drd(FMaxMinHelper(drs1(), drs2(), MaxMinKind::kMin));
          break;
        }
        case 0b001: {  // RO_FMAX_D
          set_drd(FMaxMinHelper(drs1(), drs2(), MaxMinKind::kMax));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case (RO_FCVT_S_D & kRFPTypeMask): {
      if (instr_.Rs2Value() == 0b00001) {
        auto fn = [](double drs) { return static_cast<float>(drs); };
        set_frd(CanonicalizeDoubleToFloatOperation(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FCVT_D_S: {
      if (instr_.Rs2Value() == 0b00000) {
        auto fn = [](float frs) { return static_cast<double>(frs); };
        set_drd(CanonicalizeFloatToDoubleOperation(fn));
      } else {
        UNSUPPORTED();
      }
      break;
    }
    case RO_FLE_D: {  // RO_FEQ_D RO_FLT_D RO_FLE_D
      switch (instr_.Funct3Value()) {
        case 0b010: {  // RO_FEQ_S
          set_rd(CompareFHelper(drs1(), drs2(), EQ));
          break;
        }
        case 0b001: {  // RO_FLT_D
          set_rd(CompareFHelper(drs1(), drs2(), LT));
          break;
        }
        case 0b000: {  // RO_FLE_D
          set_rd(CompareFHelper(drs1(), drs2(), LE));
          break;
        }
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case (RO_FCLASS_D & kRFPTypeMask): {  // RO_FCLASS_D , 64D RO_FMV_X_D
      if (instr_.Rs2Value() != 0b00000) {
        UNSUPPORTED();
      }
      switch (instr_.Funct3Value()) {
        case 0b001: {  // RO_FCLASS_D
          set_rd(FclassHelper(drs1()));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b000: {  // RO_FMV_X_D
          set_rd(base::bit_cast<int64_t>(drs1()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_W_D: {  // RO_FCVT_WU_D , 64F RO_FCVT_L_D RO_FCVT_LU_D
      double original_val = drs1();
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_W_D
          set_rd(RoundF2IHelper<int32_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00001: {  // RO_FCVT_WU_D
          set_rd(sext32(
              RoundF2IHelper<uint32_t>(original_val, instr_.RoundMode())));
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_L_D
          set_rd(RoundF2IHelper<int64_t>(original_val, instr_.RoundMode()));
          break;
        }
        case 0b00011: {  // RO_FCVT_LU_D
          set_rd(RoundF2IHelper<uint64_t>(original_val, instr_.RoundMode()));
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
    case RO_FCVT_D_W: {  // RO_FCVT_D_WU , 64F RO_FCVT_D_L RO_FCVT_D_LU
      switch (instr_.Rs2Value()) {
        case 0b00000: {  // RO_FCVT_D_W
          set_drd((int32_t)rs1());
          break;
        }
        case 0b00001: {  // RO_FCVT_D_WU
          set_drd((uint32_t)rs1());
          break;
        }
#ifdef V8_TARGET_ARCH_RISCV64
        case 0b00010: {  // RO_FCVT_D_L
          set_drd((int64_t)rs1());
          break;
        }
        case 0b00011: {  // RO_FCVT_D_LU
          set_drd((uint64_t)rs1());
          break;
        }
#endif /* V8_TARGET_ARCH_RISCV64 */
        default: {
          UNSUPPORTED();
        }
      }
      break;
    }
#ifdef V8_TARGET_ARCH_RISCV64
    case RO_FMV_D_X: {
      if (instr_.Funct3Value() == 0b000 && instr_.Rs2Value() == 0b00000) {
        // Since FMV preserves source bit-pattern, no need to canonize
        set_drd(base::bit_cast<double>(rs1()));
      } else {
        UNSUPPORTED();
      }
      break;
    }
#endif /* V8_TARGET_ARCH_RISCV64 */
    default: {
      UNSUPPORTED();
    }
  }
}

void Simulator::DecodeRVR4Type() {
  switch (instr_.InstructionBits() & kR4TypeMask) {
    // TODO(riscv): use F Extension macro block
    case RO_FMADD_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fadd(frs1 * frs2, frs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return std::fma(frs1, frs2, frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    case RO_FMSUB_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fsub(frs1 * frs2, frs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return std::fma(frs1, frs2, -frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    case RO_FNMSUB_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fsub(frs3, frs1 * frs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return -std::fma(frs1, frs2, -frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    case RO_FNMADD_S: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](float frs1, float frs2, float frs3) {
        if (is_invalid_fmul(frs1, frs2) || is_invalid_fadd(frs1 * frs2, frs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<float>::quiet_NaN();
        } else {
          return -std::fma(frs1, frs2, frs3);
        }
      };
      set_frd(CanonicalizeFPUOp3<float>(fn));
      break;
    }
    // TODO(riscv): use F Extension macro block
    case RO_FMADD_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fadd(drs1 * drs2, drs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return std::fma(drs1, drs2, drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    case RO_FMSUB_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fsub(drs1 * drs2, drs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return std::fma(drs1, drs2, -drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    case RO_FNMSUB_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fsub(drs3, drs1 * drs2)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return -std::fma(drs1, drs2, -drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    case RO_FNMADD_D: {
      // TODO(riscv): use rm value (round mode)
      auto fn = [this](double drs1, double drs2, double drs3) {
        if (is_invalid_fmul(drs1, drs2) || is_invalid_fadd(drs1 * drs2, drs3)) {
          this->set_fflags(kInvalidOperation);
          return std::numeric_limits<double>::quiet_NaN();
        } else {
          return -std::fma(drs1, drs2, drs3);
        }
      };
      set_drd(CanonicalizeFPUOp3<double>(fn));
      break;
    }
    default:
      UNSUPPORTED();
  }
}

#ifdef CAN_USE_RVV_INSTRUCTIONS
bool Simulator::DecodeRvvVL() {
  uint32_t instr_temp =
      instr_.InstructionBits() & (kRvvMopMask | kRvvNfMask | kBaseOpcodeMask);
  if (RO_V_VL == instr_temp) {
    if (!(instr_.InstructionBits() & (kRvvRs2Mask))) {
      switch (instr_.vl_vs_width()) {
        case 8: {
          RVV_VI_LD(0, (i * nf + fn), int8, false);
          break;
        }
        case 16: {
          RVV_VI_LD(0, (i * nf + fn), int16, false);
          break;
        }
        case 32: {
          RVV_VI_LD(0, (i * nf + fn), int32, false);
          break;
        }
        case 64: {
          RVV_VI_LD(0, (i * nf + fn), int64, false);
          break;
        }
        default:
          UNIMPLEMENTED_RISCV();
          break;
      }
      return true;
    } else {
      UNIMPLEMENTED_RISCV();
      return true;
    }
  } else if (RO_V_VLS == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VLX == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VLSEG2 == instr_temp || RO_V_VLSEG3 == instr_temp ||
             RO_V_VLSEG4 == instr_temp || RO_V_VLSEG5 == instr_temp ||
             RO_V_VLSEG6 == instr_temp || RO_V_VLSEG7 == instr_temp ||
             RO_V_VLSEG8 == instr_temp) {
    if (!(instr_.InstructionBits() & (kRvvRs2Mask))) {
      UNIMPLEMENTED_RISCV();
      return true;
    } else {
      UNIMPLEMENTED_RISCV();
      return true;
    }
  } else if (RO_V_VLSSEG2 == instr_temp || RO_V_VLSSEG3 == instr_temp ||
             RO_V_VLSSEG4 == instr_temp || RO_V_VLSSEG5 == instr_temp ||
             RO_V_VLSSEG6 == instr_temp || RO_V_VLSSEG7 == instr_temp ||
             RO_V_VLSSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VLXSEG2 == instr_temp || RO_V_VLXSEG3 == instr_temp ||
             RO_V_VLXSEG4 == instr_temp || RO_V_VLXSEG5 == instr_temp ||
             RO_V_VLXSEG6 == instr_temp || RO_V_VLXSEG7 == instr_temp ||
             RO_V_VLXSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else {
    return false;
  }
}

bool Simulator::DecodeRvvVS() {
  uint32_t instr_temp =
      instr_.InstructionBits() & (kRvvMopMask | kRvvNfMask | kBaseOpcodeMask);
  if (RO_V_VS == instr_temp) {
    if (!(instr_.InstructionBits() & (kRvvRs2Mask))) {
      switch (instr_.vl_vs_width()) {
        case 8: {
          RVV_VI_ST(0, (i * nf + fn), uint8, false);
          break;
        }
        case 16: {
          RVV_VI_ST(0, (i * nf + fn), uint16, false);
          break;
        }
        case 32: {
          RVV_VI_ST(0, (i * nf + fn), uint32, false);
          break;
        }
        case 64: {
          RVV_VI_ST(0, (i * nf + fn), uint64, false);
          break;
        }
        default:
          UNIMPLEMENTED_RISCV();
          break;
      }
    } else {
      UNIMPLEMENTED_RISCV();
    }
    return true;
  } else if (RO_V_VSS == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSX == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSU == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSSEG2 == instr_temp || RO_V_VSSEG3 == instr_temp ||
             RO_V_VSSEG4 == instr_temp || RO_V_VSSEG5 == instr_temp ||
             RO_V_VSSEG6 == instr_temp || RO_V_VSSEG7 == instr_temp ||
             RO_V_VSSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSSSEG2 == instr_temp || RO_V_VSSSEG3 == instr_temp ||
             RO_V_VSSSEG4 == instr_temp || RO_V_VSSSEG5 == instr_temp ||
             RO_V_VSSSEG6 == instr_temp || RO_V_VSSSEG7 == instr_temp ||
             RO_V_VSSSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else if (RO_V_VSXSEG2 == instr_temp || RO_V_VSXSEG3 == instr_temp ||
             RO_V_VSXSEG4 == instr_temp || RO_V_VSXSEG5 == instr_temp ||
             RO_V_VSXSEG6 == instr_temp || RO_V_VSXSEG7 == instr_temp ||
             RO_V_VSXSEG8 == instr_temp) {
    UNIMPLEMENTED_RISCV();
    return true;
  } else {
    return false;
  }
}
#endif

Builtin Simulator::LookUp(Address pc) {
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    if (builtins_.code(builtin)->contains(isolate_, pc)) return builtin;
  }
  return Builtin::kNoBuiltinId;
}

void Simulator::DecodeRVIType() {
  switch (instr_.InstructionBits() & kITypeMask) {
    case RO_JALR: {
      set_rd(get_pc() + kInstrSize);
      // Note: No need to shift 2 for JALR's imm12, but set lowest bit to 0.
      sreg_t next_pc = (rs1() + imm12()) 
"""


```