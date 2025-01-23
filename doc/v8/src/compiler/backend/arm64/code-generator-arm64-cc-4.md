Response:
My thought process to analyze the provided code snippet and answer the user's request would be as follows:

1. **Understand the Context:** The user explicitly states this is a part of `v8/src/compiler/backend/arm64/code-generator-arm64.cc`. This immediately tells me it's about code generation for the ARM64 architecture within the V8 JavaScript engine's optimizing compiler (TurboFan). The "Part 5 of 6" indicates this is a piece of a larger file, likely focusing on a specific set of functionalities.

2. **Identify Key Data Structures and Classes:** I scan the code for prominent V8-specific types and classes. I see:
    * `CodeGenerator`: This is the central class responsible for converting the intermediate representation (IR) into machine code.
    * `Instruction`: Represents a single operation in the IR.
    * `Arm64OperandConverter`: Helps extract operands (registers, immediates, memory locations) from the `Instruction` in an ARM64-specific way.
    * `MacroAssembler`: A low-level assembler for generating ARM64 instructions. The `masm()` method provides access to it.
    * `Label`: Used for branching and control flow.
    * `Register`, `VRegister`, `Simd128Register`: Represent CPU registers, vector registers, and SIMD registers respectively.
    * `FlagsCondition`: Represents the condition codes (e.g., equal, not equal, greater than) used in conditional instructions.
    * `BranchInfo`:  Holds information about branches (target labels, conditions).
    * `Frame`: Represents the stack frame for a function call.
    * `CallDescriptor`: Describes the calling convention of a function.
    * `MachineRepresentation`:  Represents the data type (e.g., int32, float64, object).
    * `WasmOutOfLineTrap`:  Specifically for WebAssembly trap handling.
    * Various constants and macros (e.g., `kArm64I64x2AllTrue`, `SIMD_REDUCE_OP_CASE`).

3. **Analyze the Functionality of Code Blocks:** I go through the code blocks, identifying the operations they perform:

    * **SIMD Instruction Assembly (`AssembleArchSimd`)**:  This block is clearly handling the generation of ARM64 NEON (SIMD) instructions based on the `Instruction`'s opcode. It uses a switch statement to handle different SIMD operations like `AllTrue`, `AnyTrue`, and lane swizzling. The `#ifdef V8_ENABLE_WEBASSEMBLY` suggests some of these are specific to WebAssembly.

    * **Branch Instruction Assembly (`AssembleArchBranch`, `AssembleArchDeoptBranch`, `AssembleArchJumpRegardlessOfAssemblyOrder`)**:  These functions handle generating branch instructions (conditional and unconditional jumps) based on the `Instruction` and `BranchInfo`. They check the `arch_opcode` and `condition` to emit the correct ARM64 branch instruction (`B`, `Cbz`, `Cbnz`, `Tbz`, `Tbnz`).

    * **Boolean Materialization (`AssembleArchBoolean`)**:  This section generates code to set a register to 1 or 0 based on a condition. It uses the `Cset` instruction.

    * **Conditional Compare and Boolean/Branch (`AssembleConditionalCompareChain`, `AssembleArchConditionalBoolean`, `AssembleArchConditionalBranch`)**: This is a more complex area dealing with chains of conditional compare instructions (`ccmp`) and then setting a register or branching based on the final condition. The input ordering to the instruction is important here.

    * **Select Instruction (`AssembleArchSelect`)**: This generates code for conditional selection (like a ternary operator) using the `Fcsel` (floating-point) and `Csel` (integer) instructions.

    * **Switch Statements (`AssembleArchBinarySearchSwitch`, `AssembleArchTableSwitch`, `AssembleJumpTable`)**: These handle the generation of code for different kinds of switch statements, including binary search and jump tables.

    * **Frame Management (`FinishFrame`, `AssembleConstructFrame`, `AssembleReturn`, `AssembleDeconstructFrame`)**:  These functions manage the creation and destruction of the stack frame, saving and restoring registers, and handling function returns. The `#if V8_ENABLE_WEBASSEMBLY` sections show special handling for WebAssembly function calls.

    * **Deoptimization (`PrepareForDeoptimizationExits`)**: This section prepares the code for deoptimization, where optimized code needs to revert to less optimized code. It sets up jumps to deoptimization entry points.

    * **Stack Manipulation (`Push`, `Pop`, `PopTempStackSlots`)**: These functions handle pushing and popping values from the stack, used for temporary storage.

    * **Move with Temporary Location (`MoveToTempLocation`, `MoveTempLocationTo`)**: This likely deals with moving values between registers and memory, potentially using a temporary register or stack slot to avoid conflicts.

4. **Relate to JavaScript Functionality (if applicable):**  Many of these code generation functions directly support JavaScript features. For example:
    * **SIMD instructions:** Directly map to JavaScript's SIMD API (`Float32x4`, `Int32x4`, etc.).
    * **Branch instructions:** Implement control flow in JavaScript (if/else, loops).
    * **Boolean materialization:** Used for boolean operators and comparisons.
    * **Conditional select:**  Can be used to implement ternary operators.
    * **Switch statements:** Implement JavaScript `switch` statements.
    * **Frame management:** Essential for function calls in JavaScript.
    * **Deoptimization:** Crucial for handling cases where optimizations are no longer valid and the engine needs to fall back to less optimized code.

5. **Illustrate with JavaScript Examples:**  Based on the identified functionalities, I create simple JavaScript examples. For instance, the SIMD section is linked to the `SIMD` API. Branches are linked to `if/else`. Switch statements are linked to `switch`.

6. **Infer Code Logic and Provide Examples:** For functions with specific logic (like `AssembleArchSimd` with its switch cases), I would:
    * **Hypothesize Inputs:** Choose specific values for the input `Instruction`'s opcode and operands.
    * **Trace the Execution:** Follow the code flow based on the hypothetical input.
    * **Determine Outputs:**  Predict what ARM64 assembly instructions would be generated.

7. **Identify Potential Programming Errors:** I consider common mistakes that could lead to the execution of the generated code failing or behaving incorrectly. Examples include incorrect type handling in SIMD operations or logic errors in conditional branches.

8. **Summarize the Functionality:** Based on the analysis of the individual code blocks, I provide a concise summary of the overall purpose of this part of the `code-generator-arm64.cc` file. The recurring theme is translating high-level IR instructions into low-level ARM64 assembly instructions.

9. **Address Specific User Queries:** Finally, I explicitly address each part of the user's request:
    * Listing functionalities.
    * Checking for Torque source (based on the `.tq` extension - which is not present here).
    * Providing JavaScript examples.
    * Giving hypothetical input/output for logic.
    * Illustrating common programming errors.
    * Summarizing the functionality as part 5 of 6.

By following these steps, I can systematically analyze the provided C++ code snippet and generate a comprehensive and informative response that addresses all aspects of the user's query.
Based on the provided C++ code snippet from `v8/src/compiler/backend/arm64/code-generator-arm64.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code is a part of the ARM64 backend of V8's TurboFan compiler. Its primary responsibility is to **translate high-level, architecture-independent intermediate representation (IR) instructions into concrete ARM64 assembly instructions.** This is a crucial step in the compilation process, taking the optimized logic and making it executable on ARM64 processors.

Here's a breakdown of specific functionalities within the snippet:

* **SIMD Instruction Assembly (`AssembleArchSimd`)**: This function handles the generation of ARM64 NEON (SIMD) instructions. It supports various SIMD operations like:
    * **Lane Extraction/Insertion:**  Moving data between SIMD registers and general-purpose registers or other SIMD lanes.
    * **Logical Operations:** `And`, `Or`, `Xor`, `Not`.
    * **Arithmetic Operations:**  Addition, subtraction, multiplication.
    * **Comparison Operations:**  Equality checks.
    * **Reductions:** Operations like `AllTrue` and `AnyTrue` to check conditions across SIMD lanes.
    * **Swizzling:** Reordering elements within a SIMD register.
* **Branch Instruction Assembly (`AssembleArchBranch`, `AssembleArchDeoptBranch`, `AssembleArchJumpRegardlessOfAssemblyOrder`)**: These functions are responsible for generating different types of branch instructions (conditional jumps, unconditional jumps, deoptimization jumps). They analyze the condition flags and target labels to emit the appropriate ARM64 branch instructions (`B`, `Cbz`, `Cbnz`, `Tbz`, `Tbnz`).
* **Boolean Materialization (`AssembleArchBoolean`)**: This function generates code to set a register to either 1 (true) or 0 (false) based on the current processor flags (the result of a previous comparison). It uses the `Cset` instruction.
* **Conditional Compare and Select (`AssembleConditionalCompareChain`, `AssembleArchConditionalBoolean`, `AssembleArchConditionalBranch`, `AssembleArchSelect`)**: This part handles more complex conditional logic. It allows for chaining multiple conditional compare instructions (`ccmp`) and then either setting a register value based on the final condition (`AssembleArchConditionalBoolean`, `AssembleArchSelect`) or branching to a target label (`AssembleArchConditionalBranch`).
* **Switch Statement Assembly (`AssembleArchBinarySearchSwitch`, `AssembleArchTableSwitch`, `AssembleJumpTable`)**:  These functions implement different strategies for generating code for `switch` statements. `AssembleArchBinarySearchSwitch` uses a binary search approach, while `AssembleArchTableSwitch` utilizes a jump table for more efficient dispatch when the range of cases is dense. `AssembleJumpTable` emits the actual jump table data.
* **Frame Management (`FinishFrame`, `AssembleConstructFrame`, `AssembleReturn`)**: This set of functions deals with the creation and destruction of the stack frame for function calls. This includes saving and restoring registers (callee-saved registers), allocating space for local variables, and handling the return from a function. It also includes specific logic for WebAssembly function calls and handling stack overflow checks.
* **Deoptimization Handling (`PrepareForDeoptimizationExits`)**: This function prepares the code for deoptimization. Deoptimization happens when the optimized code makes assumptions that later turn out to be invalid. This function sets up jump points to deoptimization entries, allowing the execution to fall back to less optimized code.
* **Stack Manipulation (`Push`, `Pop`, `PopTempStackSlots`)**: These functions provide mechanisms for pushing and popping values onto and off of the stack. This is used for temporary storage and managing local variables.
* **Temporary Location Management (`MoveToTempLocation`, `MoveTempLocationTo`)**:  These functions are likely part of a strategy to manage register allocation and move data between registers and memory efficiently, potentially using temporary registers or stack slots to resolve conflicts or intermediate steps.

**Is it a Torque source?**

The code snippet ends with `.cc`, indicating it's a standard C++ source file. Therefore, it's **not** a V8 Torque source file. Torque files would have a `.tq` extension.

**Relationship to JavaScript Functionality and Examples:**

This code directly underpins the performance of JavaScript code executed on ARM64 architectures. Many of the operations translate directly to how JavaScript features are implemented at the machine code level:

* **SIMD Operations:** JavaScript's `SIMD` API (e.g., `Float32x4`, `Int32x4`) relies on these SIMD instructions for vectorized computations.

   ```javascript
   const a = SIMD.Float32x4(1, 2, 3, 4);
   const b = SIMD.Float32x4(5, 6, 7, 8);
   const sum = SIMD.Float32x4.add(a, b); // This would utilize ARM64 SIMD instructions
   console.log(sum); // SIMD.Float32x4(6, 8, 10, 12)
   ```

* **Conditional Statements (`if`, `else if`, `else`):** The branch instructions (`AssembleArchBranch`, etc.) are fundamental to implementing conditional logic.

   ```javascript
   let x = 10;
   if (x > 5) { // A comparison and a conditional branch will be generated
       console.log("x is greater than 5");
   } else {
       console.log("x is not greater than 5");
   }
   ```

* **Boolean Operations (`&&`, `||`, `!`):** The boolean materialization and conditional compare functions are used to evaluate logical expressions.

   ```javascript
   let a = true;
   let b = false;
   let result = a && !b; // Comparisons and logical operations are translated
   console.log(result); // true
   ```

* **Switch Statements:** The `AssembleArchTableSwitch` and `AssembleArchBinarySearchSwitch` functions directly generate the machine code for JavaScript `switch` statements.

   ```javascript
   let day = 2;
   switch (day) { // This will use either a jump table or binary search
       case 1:
           console.log("Monday");
           break;
       case 2:
           console.log("Tuesday");
           break;
       default:
           console.log("Some other day");
   }
   ```

* **Function Calls:** The frame management functions (`AssembleConstructFrame`, `AssembleReturn`) are essential for setting up and tearing down the execution context of JavaScript functions.

   ```javascript
   function add(a, b) { // Frame will be created upon calling this function
       return a + b;
   }
   let sum = add(5, 3); // Function call
   ```

**Code Logic Inference with Hypothetical Input and Output:**

Let's take the `AssembleArchSimd` function with the `kArm64I64x2AllTrue` case as an example:

**Hypothetical Input:**

Assume an `Instruction* i` where:

* `i->arch_opcode()` is `kArm64I64x2AllTrue`.
* `i->OutputRegister32()` returns register `w0`.
* `i->InputSimd128Register(0)` returns SIMD register `q1`.

**Code Logic:**

The code within the `kArm64I64x2AllTrue` case is:

```c++
case kArm64I64x2AllTrue: {
  __ I64x2AllTrue(i.OutputRegister32(), i.InputSimd128Register(0));
  break;
}
```

This calls the `I64x2AllTrue` macro (likely defined in `arm64/macro-assembler-arm64.h`). This macro will generate the ARM64 assembly instruction to check if both 64-bit lanes within the SIMD register `q1` are "true" (non-zero) and store the result (1 for true, 0 for false) in the 32-bit register `w0`.

**Hypothetical Output (Assembly):**

The generated assembly instruction would likely be something like:

```assembly
  // Assuming q1 contains the input SIMD value
  // ... other instructions ...
  cmeq  w0, q1.d[0], #0  // Compare the first 64-bit lane with zero, set bits if equal
  cmeq  w1, q1.d[1], #0  // Compare the second 64-bit lane with zero
  orr   w0, w0, w1      // Logical OR the results (if either is zero, w0 will have non-zero bits)
  cset  w0, eq          // Set w0 to 1 if the result of OR is zero (meaning both were non-zero), otherwise 0
  // ... rest of the code ...
```

**Common Programming Errors (Leading to Issues in Generated Code):**

* **Incorrect Operand Types in SIMD Operations:** Trying to perform an operation on SIMD registers with incompatible data types (e.g., adding a float vector to an integer vector). This would lead to incorrect assembly instructions and potential crashes or unexpected results.
* **Off-by-One Errors in Loop Conditions:**  Incorrectly setting up loop conditions can lead to branches jumping to the wrong locations, causing infinite loops or skipping important code.
* **Mismatched Register Allocation:** Incorrectly assuming a value is in a specific register when it's not. This can happen if the compiler's register allocation logic isn't handled correctly in the code generator.
* **Incorrect Stack Frame Setup:**  Errors in `AssembleConstructFrame` or `AssembleReturn` can lead to stack corruption, causing crashes or unpredictable behavior. For example, not saving or restoring enough registers, or miscalculating the stack pointer adjustments.
* **Logic Errors in Conditional Jumps:**  Using the wrong condition codes or target labels in branch instructions can result in incorrect control flow, leading to bugs.

**Summary of Functionality (Part 5 of 6):**

This specific part of `v8/src/compiler/backend/arm64/code-generator-arm64.cc` focuses on **generating ARM64 assembly code for a significant portion of the core computational and control flow operations** needed to execute JavaScript code. It handles:

* **SIMD vector operations for optimized data processing.**
* **Branching and conditional logic for implementing control flow statements.**
* **Management of the function call stack frame.**
* **Handling of switch statements for efficient multi-way branching.**
* **Preparation for deoptimization scenarios.**
* **Basic stack manipulation for temporary storage.**

It's a crucial component in bridging the gap between the optimized, architecture-independent representation of JavaScript code and its execution on ARM64 hardware. The subsequent parts (likely Part 6) would probably cover other aspects like function calls to external code, garbage collection integration, or other specialized instructions.

### 提示词
```
这是目录为v8/src/compiler/backend/arm64/code-generator-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/arm64/code-generator-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
, i.OutputSimd128Register().V2S());
      break;
    }
    case kArm64I64x2AllTrue: {
      __ I64x2AllTrue(i.OutputRegister32(), i.InputSimd128Register(0));
      break;
    }
    case kArm64V128AnyTrue: {
      UseScratchRegisterScope scope(masm());
      // For AnyTrue, the format does not matter; also, we would like to avoid
      // an expensive horizontal reduction.
      VRegister temp = scope.AcquireV(kFormat4S);
      __ Umaxp(temp, i.InputSimd128Register(0).V4S(),
               i.InputSimd128Register(0).V4S());
      __ Fmov(i.OutputRegister64(), temp.D());
      __ Cmp(i.OutputRegister64(), 0);
      __ Cset(i.OutputRegister32(), ne);
      break;
    }
    case kArm64S32x4OneLaneSwizzle: {
      Simd128Register dst = i.OutputSimd128Register().V4S(),
                      src = i.InputSimd128Register(0).V4S();
      int from = i.InputInt32(1);
      int to = i.InputInt32(2);
      if (dst != src) {
        __ Mov(dst, src);
      }
      __ Mov(dst, to, src, from);
      break;
    }
#define SIMD_REDUCE_OP_CASE(Op, Instr, format, FORMAT)     \
  case Op: {                                               \
    UseScratchRegisterScope scope(masm());                 \
    VRegister temp = scope.AcquireV(format);               \
    __ Instr(temp, i.InputSimd128Register(0).V##FORMAT()); \
    __ Umov(i.OutputRegister32(), temp, 0);                \
    __ Cmp(i.OutputRegister32(), 0);                       \
    __ Cset(i.OutputRegister32(), ne);                     \
    break;                                                 \
  }
      SIMD_REDUCE_OP_CASE(kArm64I32x4AllTrue, Uminv, kFormatS, 4S);
      SIMD_REDUCE_OP_CASE(kArm64I16x8AllTrue, Uminv, kFormatH, 8H);
      SIMD_REDUCE_OP_CASE(kArm64I8x16AllTrue, Uminv, kFormatB, 16B);
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  return kSuccess;
}

#undef SIMD_UNOP_CASE
#undef SIMD_UNOP_LANE_SIZE_CASE
#undef SIMD_BINOP_CASE
#undef SIMD_BINOP_LANE_SIZE_CASE
#undef SIMD_DESTRUCTIVE_BINOP_CASE
#undef SIMD_DESTRUCTIVE_BINOP_LANE_SIZE_CASE
#undef SIMD_DESTRUCTIVE_RELAXED_FUSED_CASE
#undef SIMD_REDUCE_OP_CASE
#undef ASSEMBLE_SIMD_SHIFT_LEFT
#undef ASSEMBLE_SIMD_SHIFT_RIGHT

// Assemble branches after this instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Arm64OperandConverter i(this, instr);
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;
  FlagsCondition condition = branch->condition;
  ArchOpcode opcode = instr->arch_opcode();

  if (opcode == kArm64CompareAndBranch32) {
    switch (condition) {
      case kEqual:
        __ Cbz(i.InputRegister32(0), tlabel);
        break;
      case kNotEqual:
        __ Cbnz(i.InputRegister32(0), tlabel);
        break;
      default:
        UNREACHABLE();
    }
  } else if (opcode == kArm64CompareAndBranch) {
    switch (condition) {
      case kEqual:
        __ Cbz(i.InputRegister64(0), tlabel);
        break;
      case kNotEqual:
        __ Cbnz(i.InputRegister64(0), tlabel);
        break;
      default:
        UNREACHABLE();
    }
  } else if (opcode == kArm64TestAndBranch32) {
    switch (condition) {
      case kEqual:
        __ Tbz(i.InputRegister32(0), i.InputInt5(1), tlabel);
        break;
      case kNotEqual:
        __ Tbnz(i.InputRegister32(0), i.InputInt5(1), tlabel);
        break;
      default:
        UNREACHABLE();
    }
  } else if (opcode == kArm64TestAndBranch) {
    switch (condition) {
      case kEqual:
        __ Tbz(i.InputRegister64(0), i.InputInt6(1), tlabel);
        break;
      case kNotEqual:
        __ Tbnz(i.InputRegister64(0), i.InputInt6(1), tlabel);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    Condition cc = FlagsConditionToCondition(condition);
    __ B(cc, tlabel);
  }
  if (!branch->fallthru) __ B(flabel);  // no fallthru to flabel.
}

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ B(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  auto ool = zone()->New<WasmOutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  Condition cc = FlagsConditionToCondition(condition);
  __ B(cc, tlabel);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assemble boolean materializations after this instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  Arm64OperandConverter i(this, instr);

  // Materialize a full 64-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  Condition cc = FlagsConditionToCondition(condition);
  __ Cset(reg, cc);
}

// Given condition, return a value for nzcv which represents it. This is used
// for the default condition for ccmp.
inline StatusFlags ConditionToDefaultFlags(Condition condition) {
  switch (condition) {
    default:
      UNREACHABLE();
    case eq:
      return ZFlag;  // Z == 1
    case ne:
      return NoFlag;  // Z == 0
    case hs:
      return CFlag;  // C == 1
    case lo:
      return NoFlag;  // C == 0
    case mi:
      return NFlag;  // N == 1
    case pl:
      return NoFlag;  // N == 0
    case vs:
      return VFlag;  // V == 1
    case vc:
      return NoFlag;  // V == 0
    case hi:
      return CFlag;  // C == 1 && Z == 0
    case ls:
      return NoFlag;  // C == 0 || Z == 1
    case ge:
      return NoFlag;  // N == V
    case lt:
      return NFlag;  // N != V
    case gt:
      return NoFlag;  // Z == 0 && N == V
    case le:
      return ZFlag;  // Z == 1 || N != V
  }
}

void AssembleConditionalCompareChain(Instruction* instr, int64_t num_ccmps,
                                     size_t ccmp_base_index,
                                     CodeGenerator* gen) {
  Arm64OperandConverter i(gen, instr);
  // The first two, or three operands are the compare that begins the chain.
  // These operands are used when the first compare, the one with the
  // continuation attached, is generated.
  // Then, each five provide:
  //  - cmp opcode
  //  - compare lhs
  //  - compare rhs
  //  - default flags
  //  - user condition
  for (unsigned n = 0; n < num_ccmps; ++n) {
    size_t opcode_index = ccmp_base_index + kCcmpOffsetOfOpcode;
    size_t compare_lhs_index = ccmp_base_index + kCcmpOffsetOfLhs;
    size_t compare_rhs_index = ccmp_base_index + kCcmpOffsetOfRhs;
    size_t default_condition_index =
        ccmp_base_index + kCcmpOffsetOfDefaultFlags;
    size_t compare_condition_index =
        ccmp_base_index + kCcmpOffsetOfCompareCondition;
    ccmp_base_index += kNumCcmpOperands;
    DCHECK_LT(ccmp_base_index, instr->InputCount() - 1);

    InstructionCode code = static_cast<InstructionCode>(
        i.ToConstant(instr->InputAt(opcode_index)).ToInt64());

    FlagsCondition default_condition = static_cast<FlagsCondition>(
        i.ToConstant(instr->InputAt(default_condition_index)).ToInt64());

    StatusFlags default_flags =
        ConditionToDefaultFlags(FlagsConditionToCondition(default_condition));

    FlagsCondition compare_condition = static_cast<FlagsCondition>(
        i.ToConstant(instr->InputAt(compare_condition_index)).ToInt64());

    if (code == kArm64Cmp) {
      gen->masm()->Ccmp(i.InputRegister64(compare_lhs_index),
                        i.InputOperand64(compare_rhs_index), default_flags,
                        FlagsConditionToCondition(compare_condition));
    } else {
      DCHECK_EQ(code, kArm64Cmp32);
      gen->masm()->Ccmp(i.InputRegister32(compare_lhs_index),
                        i.InputOperand32(compare_rhs_index), default_flags,
                        FlagsConditionToCondition(compare_condition));
    }
  }
}

// Assemble a conditional compare and boolean materializations after this
// instruction.
void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  // Materialize a full 64-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Arm64OperandConverter i(this, instr);
  Register reg = i.OutputRegister(instr->OutputCount() - 1);
  DCHECK_GE(instr->InputCount(), 6);

  // Input ordering:
  // > InputCount - 1: number of ccmps.
  // > InputCount - 2: branch condition.
  size_t num_ccmps_index =
      instr->InputCount() - kConditionalSetEndOffsetOfNumCcmps;
  size_t set_condition_index =
      instr->InputCount() - kConditionalSetEndOffsetOfCondition;
  int64_t num_ccmps = i.ToConstant(instr->InputAt(num_ccmps_index)).ToInt64();
  size_t ccmp_base_index = set_condition_index - kNumCcmpOperands * num_ccmps;
  AssembleConditionalCompareChain(instr, num_ccmps, ccmp_base_index, this);

  FlagsCondition set_condition = static_cast<FlagsCondition>(
      i.ToConstant(instr->InputAt(set_condition_index)).ToInt64());
  __ Cset(reg, FlagsConditionToCondition(set_condition));
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  DCHECK_GE(instr->InputCount(), 6);
  Arm64OperandConverter i(this, instr);
  // Input ordering:
  // > InputCount - 1: false block.
  // > InputCount - 2: true block.
  // > InputCount - 3: number of ccmps.
  // > InputCount - 4: branch condition.
  size_t num_ccmps_index =
      instr->InputCount() - kConditionalBranchEndOffsetOfNumCcmps;
  int64_t num_ccmps = i.ToConstant(instr->InputAt(num_ccmps_index)).ToInt64();
  size_t ccmp_base_index = instr->InputCount() -
                           kConditionalBranchEndOffsetOfCondition -
                           kNumCcmpOperands * num_ccmps;
  AssembleConditionalCompareChain(instr, num_ccmps, ccmp_base_index, this);
  Condition cc = FlagsConditionToCondition(branch->condition);
  __ B(cc, branch->true_label);
  if (!branch->fallthru) __ B(branch->false_label);
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  Arm64OperandConverter i(this, instr);
  // The result register is always the last output of the instruction.
  size_t output_index = instr->OutputCount() - 1;
  MachineRepresentation rep =
      LocationOperand::cast(instr->OutputAt(output_index))->representation();
  Condition cc = FlagsConditionToCondition(condition);
  // We don't now how many inputs were consumed by the condition, so we have to
  // calculate the indices of the last two inputs.
  DCHECK_GE(instr->InputCount(), 2);
  size_t true_value_index = instr->InputCount() - 2;
  size_t false_value_index = instr->InputCount() - 1;
  if (rep == MachineRepresentation::kFloat32) {
    __ Fcsel(i.OutputFloat32Register(output_index),
             i.InputFloat32OrFPZeroRegister(true_value_index),
             i.InputFloat32OrFPZeroRegister(false_value_index), cc);
  } else if (rep == MachineRepresentation::kFloat64) {
    __ Fcsel(i.OutputFloat64Register(output_index),
             i.InputFloat64OrFPZeroRegister(true_value_index),
             i.InputFloat64OrFPZeroRegister(false_value_index), cc);
  } else if (rep == MachineRepresentation::kWord32) {
    __ Csel(i.OutputRegister32(output_index),
            i.InputOrZeroRegister32(true_value_index),
            i.InputOrZeroRegister32(false_value_index), cc);
  } else {
    DCHECK_EQ(rep, MachineRepresentation::kWord64);
    __ Csel(i.OutputRegister64(output_index),
            i.InputOrZeroRegister64(true_value_index),
            i.InputOrZeroRegister64(false_value_index), cc);
  }
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  Arm64OperandConverter i(this, instr);
  Register input = i.InputRegister32(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }
  AssembleArchBinarySearchSwitchRange(input, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  Arm64OperandConverter i(this, instr);
  UseScratchRegisterScope scope(masm());
  Register input = i.InputRegister64(0);
  size_t const case_count = instr->InputCount() - 2;

  base::Vector<Label*> cases = zone()->AllocateVector<Label*>(case_count);
  for (size_t index = 0; index < case_count; ++index) {
    cases[index] = GetLabel(i.InputRpo(index + 2));
  }
  Label* fallthrough = GetLabel(i.InputRpo(1));
  __ Cmp(input, Immediate(case_count));
  __ B(fallthrough, hs);

  Label* const jump_table = AddJumpTable(cases);
  Register addr = scope.AcquireX();
  __ Adr(addr, jump_table, MacroAssembler::kAdrFar);
  Register offset = scope.AcquireX();
  // Load the 32-bit offset.
  __ Ldrsw(offset, MemOperand(addr, input, LSL, 2));
  // The offset is relative to the address of 'jump_table', so add 'offset'
  // to 'addr' to reconstruct the absolute address.
  __ Add(addr, addr, offset);
  __ Br(addr);
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  const size_t jump_table_size = targets.size() * kInt32Size;
  MacroAssembler::BlockPoolsScope no_pool_inbetween(masm(), jump_table_size);
  int table_pos = __ pc_offset();
  // Store 32-bit pc-relative offsets.
  for (auto* target : targets) {
    __ dc32(target->pos() - table_pos);
  }
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  // Save FP registers.
  CPURegList saves_fp =
      CPURegList(kDRegSizeInBits, call_descriptor->CalleeSavedFPRegisters());
  int saved_count = saves_fp.Count();
  if (saved_count != 0) {
    DCHECK(saves_fp.bits() == CPURegList::GetCalleeSavedV().bits());
    frame->AllocateSavedCalleeRegisterSlots(saved_count *
                                            (kDoubleSize / kSystemPointerSize));
  }

  CPURegList saves =
      CPURegList(kXRegSizeInBits, call_descriptor->CalleeSavedRegisters());
  saved_count = saves.Count();
  if (saved_count != 0) {
    frame->AllocateSavedCalleeRegisterSlots(saved_count);
  }
  frame->AlignFrame(16);
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();
  __ AssertSpAligned();

  // The frame has been previously padded in CodeGenerator::FinishFrame().
  DCHECK_EQ(frame()->GetTotalFrameSlotCount() % 2, 0);
  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();

  CPURegList saves =
      CPURegList(kXRegSizeInBits, call_descriptor->CalleeSavedRegisters());
  DCHECK_EQ(saves.Count() % 2, 0);
  CPURegList saves_fp =
      CPURegList(kDRegSizeInBits, call_descriptor->CalleeSavedFPRegisters());
  DCHECK_EQ(saves_fp.Count() % 2, 0);
  // The number of return slots should be even after aligning the Frame.
  const int returns = frame()->GetReturnSlotCount();
  DCHECK_EQ(returns % 2, 0);

  if (frame_access_state()->has_frame()) {
    // Link the frame
    if (call_descriptor->IsJSFunctionCall()) {
      static_assert(StandardFrameConstants::kFixedFrameSize % 16 == 8);
      DCHECK_EQ(required_slots % 2, 1);
      __ Prologue();
      // Update required_slots count since we have just claimed one extra slot.
      static_assert(MacroAssembler::kExtraSlotClaimedByPrologue == 1);
      required_slots -= MacroAssembler::kExtraSlotClaimedByPrologue;
#if V8_ENABLE_WEBASSEMBLY
    } else if (call_descriptor->IsWasmFunctionCall() ||
               call_descriptor->IsWasmCapiFunction() ||
               call_descriptor->IsWasmImportWrapper() ||
               (call_descriptor->IsCFunctionCall() &&
                info()->GetOutputStackFrameType() ==
                    StackFrame::C_WASM_ENTRY)) {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.AcquireX();
      __ Mov(scratch,
             StackFrame::TypeToMarker(info()->GetOutputStackFrameType()));
      __ Push<MacroAssembler::kSignLR>(lr, fp, scratch,
                                       kWasmImplicitArgRegister);
      static constexpr int kSPToFPDelta = 2 * kSystemPointerSize;
      __ Add(fp, sp, kSPToFPDelta);
      if (call_descriptor->IsWasmCapiFunction()) {
        // The C-API function has one extra slot for the PC.
        required_slots++;
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    } else if (call_descriptor->kind() == CallDescriptor::kCallCodeObject) {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.AcquireX();
      __ Mov(scratch,
             StackFrame::TypeToMarker(info()->GetOutputStackFrameType()));
      __ Push<MacroAssembler::kSignLR>(lr, fp, scratch, padreg);
      static constexpr int kSPToFPDelta = 2 * kSystemPointerSize;
      __ Add(fp, sp, kSPToFPDelta);
      // One of the extra slots has just been claimed when pushing the padreg.
      // We also know that we have at least one slot to claim here, as the typed
      // frame has an odd number of fixed slots, and all other parts of the
      // total frame slots are even, leaving {required_slots} to be odd.
      DCHECK_GE(required_slots, 1);
      required_slots--;
    } else {
      __ Push<MacroAssembler::kSignLR>(lr, fp);
      __ Mov(fp, sp);
    }
    unwinding_info_writer_.MarkFrameConstructed(__ pc_offset());

    // Create OSR entry if applicable
    if (info()->is_osr()) {
      // TurboFan OSR-compiled functions cannot be entered directly.
      __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

      // Unoptimized code jumps directly to this entrypoint while the
      // unoptimized frame is still on the stack. Optimized code uses OSR values
      // directly from the unoptimized frame. Thus, all that needs to be done is
      // to allocate the remaining stack slots.
      __ RecordComment("-- OSR entrypoint --");
      osr_pc_offset_ = __ pc_offset();
      __ CodeEntry();
      size_t unoptimized_frame_slots = osr_helper()->UnoptimizedFrameSlots();
      DCHECK(call_descriptor->IsJSFunctionCall());
      DCHECK_EQ(unoptimized_frame_slots % 2, 1);
      // One unoptimized frame slot has already been claimed when the actual
      // arguments count was pushed.
      required_slots -=
          unoptimized_frame_slots - MacroAssembler::kExtraSlotClaimedByPrologue;
    }

#if V8_ENABLE_WEBASSEMBLY
    if (info()->IsWasm() && required_slots * kSystemPointerSize > 4 * KB) {
      // For WebAssembly functions with big frames we have to do the stack
      // overflow check before we construct the frame. Otherwise we may not
      // have enough space on the stack to call the runtime for the stack
      // overflow.
      Label done;
      // If the frame is bigger than the stack, we throw the stack overflow
      // exception unconditionally. Thereby we can avoid the integer overflow
      // check in the condition code.
      if (required_slots * kSystemPointerSize < v8_flags.stack_size * KB) {
        UseScratchRegisterScope temps(masm());
        Register stack_limit = temps.AcquireX();
        __ LoadStackLimit(stack_limit, StackLimitKind::kRealStackLimit);
        __ Add(stack_limit, stack_limit, required_slots * kSystemPointerSize);
        __ Cmp(sp, stack_limit);
        __ B(hs, &done);
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        CPURegList regs_to_save(kXRegSizeInBits, RegList{});
        regs_to_save.Combine(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.Combine(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());
        for (auto reg : wasm::kGpParamRegisters) regs_to_save.Combine(reg);
        __ PushCPURegList(regs_to_save);
        __ Mov(WasmHandleStackOverflowDescriptor::GapRegister(),
               required_slots * kSystemPointerSize);
        __ Add(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
            Operand(call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                    CommonFrameConstants::kFixedFrameSizeAboveFp));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        __ PopCPURegList(regs_to_save);
      } else {
        __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
                RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        if (v8_flags.debug_code) __ Brk(0);
      }
      __ Bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    // Skip callee-saved slots, which are pushed below.
    required_slots -= saves.Count();
    required_slots -= saves_fp.Count();
    required_slots -= returns;

    __ Claim(required_slots);
  }

  // Save FP registers.
  DCHECK_IMPLIES(saves_fp.Count() != 0,
                 saves_fp.bits() == CPURegList::GetCalleeSavedV().bits());
  __ PushCPURegList(saves_fp);

  // Save registers.
  __ PushCPURegList(saves);

  if (returns != 0) {
    __ Claim(returns);
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ Str(xzr, MemOperand(fp, offset.offset()));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = RoundUp(frame()->GetReturnSlotCount(), 2);
  if (returns != 0) {
    __ Drop(returns);
  }

  // Restore registers.
  CPURegList saves =
      CPURegList(kXRegSizeInBits, call_descriptor->CalleeSavedRegisters());
  __ PopCPURegList(saves);

  // Restore fp registers.
  CPURegList saves_fp =
      CPURegList(kDRegSizeInBits, call_descriptor->CalleeSavedFPRegisters());
  __ PopCPURegList(saves_fp);

  unwinding_info_writer_.MarkBlockWillExit();

  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());
  Arm64OperandConverter g(this, nullptr);

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ cmp(g.ToRegister(additional_pop_count), Operand(0));
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue);
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.AcquireX();
      __ Ldr(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
      __ Cmp(scratch,
             Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    }
    Label done;
    __ B(ne, &done);
    CPURegList regs_to_save(kXRegSizeInBits, RegList{});
    for (auto reg : wasm::kGpReturnRegisters) regs_to_save.Combine(reg);
    __ PushCPURegList(regs_to_save);
    __ Mov(kCArgRegs[0], ExternalReference::isolate_address());
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    __ Mov(fp, kReturnRegister0);
    __ PopCPURegList(regs_to_save);
    if (masm()->options().enable_simulator_code) {
      // The next instruction after shrinking stack is leaving the frame.
      // So SP will be set to old FP there. Switch simulator stack limit here.
      UseScratchRegisterScope temps{masm()};
      temps.Exclude(x16);
      __ LoadStackLimit(x16, StackLimitKind::kRealStackLimit);
      __ hlt(kImmExceptionIsSwitchStackLimit);
    }
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  Register argc_reg = x3;
  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = parameter_slots != 0 &&
                           frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall();
  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ B(&return_label_);
        return;
      } else {
        __ Bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count.
      DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
      __ Ldr(argc_reg, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }

  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver). This
    // number of arguments is given by max(1 + argc_reg, parameter_slots).
    Label argc_reg_has_final_count;
    DCHECK(!call_descriptor->CalleeSavedRegisters().has(argc_reg));
    if (parameter_slots > 1) {
      __ Cmp(argc_reg, Operand(parameter_slots));
      __ B(&argc_reg_has_final_count, ge);
      __ Mov(argc_reg, Operand(parameter_slots));
      __ Bind(&argc_reg_has_final_count);
    }
    __ DropArguments(argc_reg);
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ DropArguments(parameter_slots + additional_count);
  } else if (parameter_slots == 0) {
    __ DropArguments(g.ToRegister(additional_pop_count));
  } else {
    // {additional_pop_count} is guaranteed to be zero if {parameter_slots !=
    // 0}. Check RawMachineAssembler::PopAndReturn.
    __ DropArguments(parameter_slots);
  }
  __ AssertSpAligned();
  __ Ret();
}

void CodeGenerator::FinishCode() { __ ForceConstantPoolEmissionWithoutJump(); }

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {
  __ ForceConstantPoolEmissionWithoutJump();
  // We are conservative here, reserving sufficient space for the largest deopt
  // kind.
  DCHECK_GE(Deoptimizer::kLazyDeoptExitSize, Deoptimizer::kEagerDeoptExitSize);
  __ CheckVeneerPool(
      false, false,
      static_cast<int>(exits->size()) * Deoptimizer::kLazyDeoptExitSize);

  // Check which deopt kinds exist in this InstructionStream object, to avoid
  // emitting jumps to unused entries.
  bool saw_deopt_kind[kDeoptimizeKindCount] = {false};
  for (auto exit : *exits) {
    saw_deopt_kind[static_cast<int>(exit->kind())] = true;
  }

  // Emit the jumps to deoptimization entries.
  UseScratchRegisterScope scope(masm());
  Register scratch = scope.AcquireX();
  static_assert(static_cast<int>(kFirstDeoptimizeKind) == 0);
  for (int i = 0; i < kDeoptimizeKindCount; i++) {
    if (!saw_deopt_kind[i]) continue;
    DeoptimizeKind kind = static_cast<DeoptimizeKind>(i);
    __ bind(&jump_deoptimization_entry_labels_[i]);
    __ LoadEntryFromBuiltin(Deoptimizer::GetDeoptimizationEntry(kind), scratch);
    __ Jump(scratch);
  }
}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = RoundUp<2>(ElementSizeInPointers(rep));
  Arm64OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ Push(padreg, g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.AcquireX();
    __ Ldr(scratch, g.ToMemOperand(source, masm()));
    __ Push(padreg, scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ Sub(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  int dropped_slots = RoundUp<2>(ElementSizeInPointers(rep));
  Arm64OperandConverter g(this, nullptr);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(g.ToRegister(dest), padreg);
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.AcquireX();
    __ Pop(scratch, padreg);
    __ Str(scratch, g.ToMemOperand(dest, masm()));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Add(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ add(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
    temp_slots_ = 0;
  }
}

void CodeGenerator::MoveToTempLocation(InstructionOperand* source,
                                       MachineRepresentation rep) {
  // Must be kept in sync with {MoveTempLocationTo}.
  DCHECK(!source->IsImmediate());
  move_cycle_.temps.emplace(masm());
  auto& temps = *move_cycle_.temps;
  // Temporarily exclude the reserved scratch registers while we pick one to
  // resolve the move cycle. Re-include them immediately afterwards as they
  // might be needed for the move to the temp location.
  temps.Exclude(CPURegList(64, move_cycle_.scratch_regs));
  temps.ExcludeFP(CPURegList(64, move_cycle_.scratch_fp_regs));
  if (!IsFloatingPoint(rep)) {
    if (temps.CanAcquire()) {
      Register scratch = move_cycle_.temps->AcquireX();
      move_cycle_.scratch_reg.emplace(scratch);
    } else if (temps.CanAcquireFP()) {
      // Try to use an FP register if no GP register is available for non-FP
      // moves.
      DoubleRegister scratch = move_cycle_.temps->AcquireD();
      move_cycle_.scratch_reg.emplace(scratch);
    }
  } else if (rep == MachineRepresentation::kFloat32) {
    VRegister scratch = move_cycle_.temps->AcquireS();
    move_cycle_.scratch_reg.emplace(scratch);
  } else if (rep == MachineRepresentation::kFloat64) {
    VRegister scratch = move_cycle_.temps->AcquireD();
    move_cycle_.scratch_reg.emplace(scratch);
  } else if (rep == MachineRepresentation::kSimd128) {
    VRegister scratch = move_cycle_.temps->AcquireQ();
    move_cycle_.scratch_reg.emplace(scratch);
  }
  temps.Include(CPURegList(64, move_cycle_.scratch_regs));
  temps.IncludeFP(CPURegList(64, move_cycle_.scratch_fp_regs));
  if (move_cycle_.scratch_reg.has_value()) {
    // A scratch register is available for this rep.
    auto& scratch_reg = *move_cycle_.scratch_reg;
    if (scratch_reg.IsD() && !IsFloatingPoint(rep)) {
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat64,
                               scratch_reg.code());
      Arm64OperandConverter g(this, nullptr);
      if (source->IsStackSlot()) {
        __ Ldr(g.ToDoubleRegister(&scratch), g.ToMemOperand(source, masm()));
      } else {
        DCHECK(source->IsRegister());
        __ fmov(g.ToDoubleRegister(&scratch), g.ToRegister(source));
      }
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                               move_cycle_.scratch_reg->code());
      AssembleMove(source, &scratch);
    }
  } else {
    // The scratch registers are blocked by pending moves. Use the stack
    // instead.
    Push(source);
  }
}

void CodeGenerator::MoveTempLocationTo(InstructionOperand* dest,
                                       MachineRepresentation rep) {
  if (move_cycle_.scratch_reg.has_value()) {
    auto& scratch_reg = *move_cycle_.scratch_
```