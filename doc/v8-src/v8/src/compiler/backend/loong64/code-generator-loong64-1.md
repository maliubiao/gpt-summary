Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a larger file.

The code seems to be part of the backend of a JavaScript compiler, specifically for the LoongArch64 architecture. It focuses on generating machine code for various operations.

Key functionalities to identify:

1. **Instruction Emission:** The code handles different instruction types (identified by `kLoong64...`) and generates the corresponding assembly instructions using a `MacroAssembler`.
2. **Data Conversion:**  It includes logic for converting between different data types (e.g., float to integer).
3. **Memory Access:**  It manages loading and storing data from memory.
4. **Atomic Operations:**  The code contains implementations for atomic memory operations.
5. **Stack Management:**  It deals with pushing and popping values from the stack, as well as frame setup and teardown.
6. **Branching and Control Flow:** It implements conditional and unconditional branching based on the results of previous operations.
7. **Boolean Materialization:** It generates code to represent boolean values (0 or 1) based on conditions.
8. **Switches:**  The code handles binary search and table switch implementations.
9. **Function Calls and Returns:**  It manages the setup and teardown of function call frames.
10. **Deoptimization:** It includes mechanisms for deoptimization, although this part is less visible in the snippet.
11. **Move Operations:**  It handles moving data between registers, stack slots, and constants.
12. **Floating-Point Operations:** It includes specific instructions for floating-point conversions, comparisons, and data manipulation.

Regarding the connection to JavaScript, the generated machine code will ultimately execute the logic of JavaScript code. For example, when a JavaScript number needs to be converted to an integer, the functions in this file will be responsible for generating the low-level assembly instructions to perform that conversion.
This C++ code snippet is part of the LoongArch64-specific code generator for the V8 JavaScript engine. It focuses on implementing the code generation logic for various intermediate representation (IR) instructions, translating them into actual LoongArch64 assembly instructions. Here's a breakdown of its functionalities:

**Core Functionality: Instruction Lowering and Assembly Generation**

This code takes high-level, architecture-neutral IR instructions and lowers them into concrete LoongArch64 assembly instructions. It uses a `MacroAssembler` object (`__`) to emit these instructions. The `switch` statement based on `instr->arch_opcode()` is the central mechanism for handling different instruction types.

**Specific Functionalities Covered in this Snippet:**

* **Floating-Point Conversions:**
    * Converting floating-point numbers (both single-precision `float` and double-precision `double`) to unsigned 32-bit and 64-bit integers (`kLoong64Float64ToUint32`, `kLoong64Float32ToUint32`, `kLoong64Float32ToUint64`, `kLoong64Float64ToUint64`). It includes handling potential overflow and NaN cases.
* **Bit Manipulation and Data Movement:**
    * Bitcasting between floating-point and integer representations (`kLoong64BitcastDL`, `kLoong64BitcastLD`).
    * Extracting high and low 32-bit words from a 64-bit floating-point number (`kLoong64Float64ExtractLowWord32`, `kLoong64Float64ExtractHighWord32`).
    * Creating a 64-bit floating-point number from a pair of 32-bit words (`kLoong64Float64FromWord32Pair`).
    * Inserting low and high 32-bit words into a 64-bit floating-point number (`kLoong64Float64InsertLowWord32`, `kLoong64Float64InsertHighWord32`).
    * Sign-extending bytes and half-words to words (`kLoong64Ext_w_b`, `kLoong64Ext_w_h`).
* **Memory Access (Loads and Stores):**
    * Loading and storing bytes, half-words, words, and double-words (`kLoong64Ld_bu`, `kLoong64Ld_b`, `kLoong64St_b`, etc.).
    * Loading and storing floating-point single and double precision values (`kLoong64Fld_s`, `kLoong64Fst_s`, `kLoong64Fld_d`, `kLoong64Fst_d`).
    * Special load/store operations for tagged pointers (used for representing JavaScript objects) with decompression and compression (`kLoong64LoadDecompressTaggedSigned`, `kLoong64StoreCompressTagged`, etc.).
* **Stack Operations:**
    * Pushing and peeking values onto/from the stack (`kLoong64Push`, `kLoong64Peek`).
    * Claiming stack space (`kLoong64StackClaim`).
    * Poking values onto the stack at an offset (`kLoong64Poke`).
* **Byte Swapping:**
    * Swapping the byte order of 32-bit and 64-bit values (`kLoong64ByteSwap64`, `kLoong64ByteSwap32`).
* **Atomic Operations:**
    * Implementing various atomic load, store, exchange, and compare-and-exchange operations for different data sizes (8-bit, 16-bit, 32-bit, 64-bit) (`kAtomicLoadInt8`, `kAtomicStoreWord32`, `kAtomicExchangeInt8`, `kAtomicCompareExchangeWord32`, `kAtomicAddWord32`, etc.). These are crucial for implementing concurrency primitives in JavaScript.
* **Data Barrier:**
    * Emitting a data barrier instruction (`kLoong64Dbar`).
* **Boolean Materialization:**
    * Generating code to represent the result of a comparison or test as a boolean value (0 or 1) (`AssembleArchBoolean`).
* **Branching and Control Flow:**
    * Implementing conditional branches based on various conditions, including comparisons, overflow checks, and floating-point comparisons (`AssembleBranchToLabels`). It handles the specifics of LoongArch64's branching without explicit condition codes.
* **Function Prologue and Epilogue:**
    * `AssembleConstructFrame`: Sets up the stack frame at the beginning of a function. This includes saving registers, allocating space for local variables, and handling stack overflow checks.
    * `AssembleReturn`: Tears down the stack frame and returns from a function, restoring saved registers and adjusting the stack pointer.
* **Move Operations:**
    * Efficiently moving data between registers, stack slots, and constants (`AssembleMove`). It includes optimizations for 32-bit moves.
* **Swap Operations:**
    * Exchanging the values of two operands (`AssembleSwap`).
* **Handling Deoptimization:**
    * `AssembleArchDeoptBranch`:  Generates a branch to a deoptimization entry point.
* **WebAssembly Support:**
    * Includes code related to WebAssembly, such as handling stack overflow checks and calls to specific builtins (`#if V8_ENABLE_WEBASSEMBLY`).

**Relationship to JavaScript Functionality:**

This code is a fundamental part of how JavaScript code is executed on LoongArch64. Here are some examples of how the generated assembly relates to JavaScript features:

* **Number Conversions:** When a JavaScript operation requires converting a floating-point number to an integer (e.g., using `parseInt` or bitwise operators), the `kLoong64Float*ToUint*` instructions will be used to generate the necessary machine code.

   ```javascript
   let floatValue = 3.14;
   let intValue = floatValue | 0; // Bitwise OR forces conversion to integer
   ```

* **Memory Access and Object Properties:** When accessing properties of JavaScript objects, the `kLoong64Ld_*` and `kLoong64St_*` instructions (potentially with decompression/compression for tagged pointers) are used to load and store the property values from memory.

   ```javascript
   let obj = { x: 10 };
   let value = obj.x; // Load
   obj.y = 20;      // Store
   ```

* **Atomic Operations and Shared Memory:** When using `SharedArrayBuffer` and atomic operations in JavaScript, the `kAtomic*` instructions will be directly translated into the corresponding LoongArch64 atomic instructions to ensure thread-safe access to shared memory.

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const view = new Int32Array(sab);
   Atomics.add(view, 0, 5);
   ```

* **Function Calls:**  When a JavaScript function is called, the `AssembleConstructFrame` function (and related code not shown in the snippet) sets up the stack frame. The `kLoong64Push` and `kLoong64Pop` instructions are used for managing arguments and local variables on the stack. The `AssembleReturn` function handles the function return.

   ```javascript
   function myFunction(a, b) {
       return a + b;
   }
   let result = myFunction(2, 3);
   ```

* **Control Flow (if/else, loops):**  JavaScript's `if` statements and loops are implemented using conditional branch instructions generated by `AssembleArchBranch`. The comparison operations that determine the branch condition will utilize instructions like `kLoong64Cmp32` or `kLoong64Float64Cmp`.

   ```javascript
   let x = 5;
   if (x > 0) {
       console.log("Positive");
   }

   for (let i = 0; i < 10; i++) {
       // ...
   }
   ```

In summary, this code snippet is a crucial part of the V8 engine's ability to execute JavaScript code efficiently on LoongArch64 processors. It bridges the gap between the high-level semantics of JavaScript and the low-level instructions understood by the hardware.

Prompt: 
```
这是目录为v8/src/compiler/backend/loong64/code-generator-loong64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
     __ movfcsr2gr(output2, FCSR2);
        // Check for overflow and NaNs.
        __ And(output2, output2,
               kFCSROverflowCauseMask | kFCSRInvalidOpCauseMask);
        __ Slt(output2, zero_reg, output2);
        __ xori(output2, output2, 1);
      }
      if (set_overflow_to_min_i64) {
        // Avoid INT64_MAX as an overflow indicator and use INT64_MIN instead,
        // because INT64_MIN allows easier out-of-bounds detection.
        __ addi_d(scratch, i.OutputRegister(), 1);
        __ slt(scratch, scratch, i.OutputRegister());
        __ add_d(i.OutputRegister(), i.OutputRegister(), scratch);
      }
      break;
    }
    case kLoong64Float64ToUint32: {
      FPURegister scratch = kScratchDoubleReg;
      __ Ftintrz_uw_d(i.OutputRegister(), i.InputDoubleRegister(0), scratch);
      if (instr->OutputCount() > 1) {
        __ li(i.OutputRegister(1), 1);
        __ Move(scratch, static_cast<double>(-1.0));
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLT);
        __ LoadZeroIfNotFPUCondition(i.OutputRegister(1));
        __ Move(scratch, static_cast<double>(UINT32_MAX) + 1);
        __ CompareF64(scratch, i.InputDoubleRegister(0), CLE);
        __ LoadZeroIfFPUCondition(i.OutputRegister(1));
      }
      break;
    }
    case kLoong64Float32ToUint32: {
      FPURegister scratch = kScratchDoubleReg;
      bool set_overflow_to_min_i32 = MiscField::decode(instr->opcode());
      __ Ftintrz_uw_s(i.OutputRegister(), i.InputDoubleRegister(0), scratch);
      if (set_overflow_to_min_i32) {
        UseScratchRegisterScope temps(masm());
        Register scratch = temps.Acquire();
        // Avoid UINT32_MAX as an overflow indicator and use 0 instead,
        // because 0 allows easier out-of-bounds detection.
        __ addi_w(scratch, i.OutputRegister(), 1);
        __ Movz(i.OutputRegister(), zero_reg, scratch);
      }
      break;
    }
    case kLoong64Float32ToUint64: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Ftintrz_ul_s(i.OutputRegister(), i.InputDoubleRegister(0), scratch,
                      result);
      break;
    }
    case kLoong64Float64ToUint64: {
      FPURegister scratch = kScratchDoubleReg;
      Register result = instr->OutputCount() > 1 ? i.OutputRegister(1) : no_reg;
      __ Ftintrz_ul_d(i.OutputRegister(0), i.InputDoubleRegister(0), scratch,
                      result);
      break;
    }
    case kLoong64BitcastDL:
      __ movfr2gr_d(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64BitcastLD:
      __ movgr2fr_d(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kLoong64Float64ExtractLowWord32:
      __ FmoveLow(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64ExtractHighWord32:
      __ movfrh2gr_s(i.OutputRegister(), i.InputDoubleRegister(0));
      break;
    case kLoong64Float64FromWord32Pair:
      __ movgr2fr_w(i.OutputDoubleRegister(), i.InputRegister(1));
      __ movgr2frh_w(i.OutputDoubleRegister(), i.InputRegister(0));
      break;
    case kLoong64Float64InsertLowWord32:
      __ FmoveLow(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
    case kLoong64Float64InsertHighWord32:
      __ movgr2frh_w(i.OutputDoubleRegister(), i.InputRegister(1));
      break;
      // ... more basic instructions ...

    case kLoong64Ext_w_b:
      __ ext_w_b(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Ext_w_h:
      __ ext_w_h(i.OutputRegister(), i.InputRegister(0));
      break;
    case kLoong64Ld_bu:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_bu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_b:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_b(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64St_b: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_b(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64Ld_hu:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_hu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_h:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_h(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64St_h: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_h(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64Ld_w:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_w(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_wu:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_wu(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64Ld_d:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Ld_d(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64St_w: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_w(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64St_d: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ St_d(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64LoadDecompressTaggedSigned:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64LoadDecompressTagged:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64LoadDecompressProtected:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ DecompressProtected(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64StoreCompressTagged: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ StoreTaggedField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64LoadDecodeSandboxedPointer:
      __ LoadSandboxedPointerField(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64StoreEncodeSandboxedPointer: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ StoreSandboxedPointerField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64StoreIndirectPointer: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ StoreIndirectPointerField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64AtomicLoadDecompressTaggedSigned:
      __ AtomicDecompressTaggedSigned(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64AtomicLoadDecompressTagged:
      __ AtomicDecompressTagged(i.OutputRegister(), i.MemoryOperand());
      break;
    case kLoong64AtomicStoreCompressTagged: {
      size_t index = 0;
      MemOperand mem = i.MemoryOperand(&index);
      __ AtomicStoreTaggedField(i.InputOrZeroRegister(index), mem);
      break;
    }
    case kLoong64Fld_s: {
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fld_s(i.OutputSingleRegister(), i.MemoryOperand());
      break;
    }
    case kLoong64Fst_s: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroSingleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fst_s(ft, operand);
      break;
    }
    case kLoong64Fld_d:
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fld_d(i.OutputDoubleRegister(), i.MemoryOperand());
      break;
    case kLoong64Fst_d: {
      size_t index = 0;
      MemOperand operand = i.MemoryOperand(&index);
      FPURegister ft = i.InputOrZeroDoubleRegister(index);
      if (ft == kDoubleRegZero && !__ IsDoubleZeroRegSet()) {
        __ Move(kDoubleRegZero, 0.0);
      }
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ Fst_d(ft, operand);
      break;
    }
    case kLoong64Dbar: {
      __ dbar(0);
      break;
    }
    case kLoong64Push:
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Fst_d(i.InputDoubleRegister(0), MemOperand(sp, -kDoubleSize));
        __ Sub_d(sp, sp, Operand(kDoubleSize));
        frame_access_state()->IncreaseSPDelta(kDoubleSize / kSystemPointerSize);
      } else {
        __ Push(i.InputRegister(0));
        frame_access_state()->IncreaseSPDelta(1);
      }
      break;
    case kLoong64Peek: {
      int reverse_slot = i.InputInt32(0);
      int offset =
          FrameSlotToFPOffset(frame()->GetTotalFrameSlotCount() - reverse_slot);
      if (instr->OutputAt(0)->IsFPRegister()) {
        LocationOperand* op = LocationOperand::cast(instr->OutputAt(0));
        if (op->representation() == MachineRepresentation::kFloat64) {
          __ Fld_d(i.OutputDoubleRegister(), MemOperand(fp, offset));
        } else if (op->representation() == MachineRepresentation::kFloat32) {
          __ Fld_s(i.OutputSingleRegister(0), MemOperand(fp, offset));
        } else {
          DCHECK_EQ(MachineRepresentation::kSimd128, op->representation());
          abort();
        }
      } else {
        __ Ld_d(i.OutputRegister(0), MemOperand(fp, offset));
      }
      break;
    }
    case kLoong64StackClaim: {
      __ Sub_d(sp, sp, Operand(i.InputInt32(0)));
      frame_access_state()->IncreaseSPDelta(i.InputInt32(0) /
                                            kSystemPointerSize);
      break;
    }
    case kLoong64Poke: {
      if (instr->InputAt(0)->IsFPRegister()) {
        __ Fst_d(i.InputDoubleRegister(0), MemOperand(sp, i.InputInt32(1)));
      } else {
        __ St_d(i.InputRegister(0), MemOperand(sp, i.InputInt32(1)));
      }
      break;
    }
    case kLoong64ByteSwap64: {
      __ ByteSwap(i.OutputRegister(0), i.InputRegister(0), 8);
      break;
    }
    case kLoong64ByteSwap32: {
      __ ByteSwap(i.OutputRegister(0), i.InputRegister(0), 4);
      break;
    }
    case kAtomicLoadInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_b);
      break;
    case kAtomicLoadUint8:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_bu);
      break;
    case kAtomicLoadInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_h);
      break;
    case kAtomicLoadUint16:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_hu);
      break;
    case kAtomicLoadWord32:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_w);
      break;
    case kLoong64Word64AtomicLoadUint32:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_wu);
      break;
    case kLoong64Word64AtomicLoadUint64:
      ASSEMBLE_ATOMIC_LOAD_INTEGER(Ld_d);
      break;
    case kAtomicStoreWord8:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_b);
      break;
    case kAtomicStoreWord16:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_h);
      break;
    case kAtomicStoreWord32:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_w);
      break;
    case kLoong64Word64AtomicStoreWord64:
      ASSEMBLE_ATOMIC_STORE_INTEGER(St_d);
      break;
    case kAtomicExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 8, 32);
      break;
    case kAtomicExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 8, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 8, 64);
          break;
      }
      break;
    case kAtomicExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 16, 32);
      break;
    case kAtomicExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 16, 32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 16, 64);
          break;
      }
      break;
    case kAtomicExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amswap_db_w(i.OutputRegister(0), i.InputRegister(2),
                         i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 32, 64);
          break;
      }
      break;
    case kLoong64Word64AtomicExchangeUint64:
      __ add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amswap_db_d(i.OutputRegister(0), i.InputRegister(2),
                     i.TempRegister(0));
      break;
    case kAtomicCompareExchangeInt8:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 8, 32);
      break;
    case kAtomicCompareExchangeUint8:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 8,
                                                       32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 8,
                                                       64);
          break;
      }
      break;
    case kAtomicCompareExchangeInt16:
      DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32);
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, true, 16, 32);
      break;
    case kAtomicCompareExchangeUint16:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_w, Sc_w, false, 16,
                                                       32);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 16,
                                                       64);
          break;
      }
      break;
    case kAtomicCompareExchangeWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ slli_w(i.InputRegister(2), i.InputRegister(2), 0);
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll_w, Sc_w);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT(Ll_d, Sc_d, false, 32,
                                                       64);
          break;
      }
      break;
    case kLoong64Word64AtomicCompareExchangeUint64:
      ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER(Ll_d, Sc_d);
      break;
    case kAtomicAddWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amadd_db_w(i.OutputRegister(0), i.InputRegister(2),
                        i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Add_d, 64);
          break;
      }
      break;
    case kAtomicSubWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          ASSEMBLE_ATOMIC_BINOP(Ll_w, Sc_w, Sub_w);
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Sub_d, 64);
          break;
      }
      break;
    case kAtomicAndWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amand_db_w(i.OutputRegister(0), i.InputRegister(2),
                        i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, And, 64);
          break;
      }
      break;
    case kAtomicOrWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amor_db_w(i.OutputRegister(0), i.InputRegister(2),
                       i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Or, 64);
          break;
      }
      break;
    case kAtomicXorWord32:
      switch (AtomicWidthField::decode(opcode)) {
        case AtomicWidth::kWord32:
          __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
          RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
          __ amxor_db_w(i.OutputRegister(0), i.InputRegister(2),
                        i.TempRegister(0));
          break;
        case AtomicWidth::kWord64:
          ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 32, Xor, 64);
          break;
      }
      break;
#define ATOMIC_BINOP_CASE(op, inst32, inst64)                          \
  case kAtomic##op##Int8:                                              \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, true, 8, inst32, 32);        \
    break;                                                             \
  case kAtomic##op##Uint8:                                             \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, false, 8, inst32, 32);   \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 8, inst64, 64);   \
        break;                                                         \
    }                                                                  \
    break;                                                             \
  case kAtomic##op##Int16:                                             \
    DCHECK_EQ(AtomicWidthField::decode(opcode), AtomicWidth::kWord32); \
    ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, true, 16, inst32, 32);       \
    break;                                                             \
  case kAtomic##op##Uint16:                                            \
    switch (AtomicWidthField::decode(opcode)) {                        \
      case AtomicWidth::kWord32:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_w, Sc_w, false, 16, inst32, 32);  \
        break;                                                         \
      case AtomicWidth::kWord64:                                       \
        ASSEMBLE_ATOMIC_BINOP_EXT(Ll_d, Sc_d, false, 16, inst64, 64);  \
        break;                                                         \
    }                                                                  \
    break;
      ATOMIC_BINOP_CASE(Add, Add_w, Add_d)
      ATOMIC_BINOP_CASE(Sub, Sub_w, Sub_d)
      ATOMIC_BINOP_CASE(And, And, And)
      ATOMIC_BINOP_CASE(Or, Or, Or)
      ATOMIC_BINOP_CASE(Xor, Xor, Xor)
#undef ATOMIC_BINOP_CASE

    case kLoong64Word64AtomicAddUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amadd_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
    case kLoong64Word64AtomicSubUint64:
      ASSEMBLE_ATOMIC_BINOP(Ll_d, Sc_d, Sub_d);
      break;
    case kLoong64Word64AtomicAndUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amand_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
    case kLoong64Word64AtomicOrUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amor_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
    case kLoong64Word64AtomicXorUint64:
      __ Add_d(i.TempRegister(0), i.InputRegister(0), i.InputRegister(1));
      RecordTrapInfoIfNeeded(zone(), this, opcode, instr, __ pc_offset());
      __ amxor_db_d(i.OutputRegister(0), i.InputRegister(2), i.TempRegister(0));
      break;
#undef ATOMIC_BINOP_CASE
    case kLoong64S128Const:
    case kLoong64S128Zero:
    case kLoong64I32x4Splat:
    case kLoong64I32x4ExtractLane:
    case kLoong64I32x4Add:
    case kLoong64I32x4ReplaceLane:
    case kLoong64I32x4Sub:
    case kLoong64F64x2Abs:
    default:
      break;
  }
  return kSuccess;
}

#define UNSUPPORTED_COND(opcode, condition)                                    \
  StdoutStream{} << "Unsupported " << #opcode << " condition: \"" << condition \
                 << "\"";                                                      \
  UNIMPLEMENTED();

void SignExtend(MacroAssembler* masm, Instruction* instr, Register* left,
                Operand* right, Register* temp0, Register* temp1) {
  bool need_signed = false;
  MachineRepresentation rep_left =
      LocationOperand::cast(instr->InputAt(0))->representation();
  need_signed = IsAnyTagged(rep_left) || IsAnyCompressed(rep_left) ||
                rep_left == MachineRepresentation::kWord64;
  if (need_signed) {
    masm->slli_w(*temp0, *left, 0);
    *left = *temp0;
  }

  if (instr->InputAt(1)->IsAnyLocationOperand()) {
    MachineRepresentation rep_right =
        LocationOperand::cast(instr->InputAt(1))->representation();
    need_signed = IsAnyTagged(rep_right) || IsAnyCompressed(rep_right) ||
                  rep_right == MachineRepresentation::kWord64;
    if (need_signed && right->is_reg()) {
      DCHECK(*temp1 != no_reg);
      masm->slli_w(*temp1, right->rm(), 0);
      *right = Operand(*temp1);
    }
  }
}

void AssembleBranchToLabels(CodeGenerator* gen, MacroAssembler* masm,
                            Instruction* instr, FlagsCondition condition,
                            Label* tlabel, Label* flabel, bool fallthru) {
#undef __
#define __ masm->
  Loong64OperandConverter i(gen, instr);

  // LOONG64 does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit loong64 pseudo-instructions, which are handled here by branch
  // instructions that do the actual comparison. Essential that the input
  // registers to compare pseudo-op are not modified before this branch op, as
  // they are tested here.

  if (instr->arch_opcode() == kLoong64Tst) {
    Condition cc = FlagsConditionToConditionTst(condition);
    __ Branch(tlabel, cc, t8, Operand(zero_reg));
  } else if (instr->arch_opcode() == kLoong64Add_d ||
             instr->arch_opcode() == kLoong64Sub_d) {
    UseScratchRegisterScope temps(masm);
    Register scratch = temps.Acquire();
    Register scratch2 = temps.Acquire();
    Condition cc = FlagsConditionToConditionOvf(condition);
    __ srai_d(scratch, i.OutputRegister(), 32);
    __ srai_w(scratch2, i.OutputRegister(), 31);
    __ Branch(tlabel, cc, scratch2, Operand(scratch));
  } else if (instr->arch_opcode() == kLoong64AddOvf_d ||
             instr->arch_opcode() == kLoong64SubOvf_d) {
    switch (condition) {
      // Overflow occurs if overflow register is negative
      case kOverflow:
        __ Branch(tlabel, lt, t8, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, ge, t8, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
  } else if (instr->arch_opcode() == kLoong64MulOvf_w ||
             instr->arch_opcode() == kLoong64MulOvf_d) {
    // Overflow occurs if overflow register is not zero
    switch (condition) {
      case kOverflow:
        __ Branch(tlabel, ne, t8, Operand(zero_reg));
        break;
      case kNotOverflow:
        __ Branch(tlabel, eq, t8, Operand(zero_reg));
        break;
      default:
        UNSUPPORTED_COND(instr->arch_opcode(), condition);
    }
  } else if (instr->arch_opcode() == kLoong64Cmp32 ||
             instr->arch_opcode() == kLoong64Cmp64) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
    // Word32Compare has two temp registers.
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kLoong64Cmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      SignExtend(masm, instr, &left, &right, &temp0, &temp1);
    }
    __ Branch(tlabel, cc, left, right);
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    DCHECK((cc == ls) || (cc == hi));
    if (cc == ls) {
      __ xori(i.TempRegister(0), i.TempRegister(0), 1);
    }
    __ Branch(tlabel, ne, i.TempRegister(0), Operand(zero_reg));
  } else if (instr->arch_opcode() == kLoong64Float32Cmp ||
             instr->arch_opcode() == kLoong64Float64Cmp) {
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    if (predicate) {
      __ BranchTrueF(tlabel);
    } else {
      __ BranchFalseF(tlabel);
    }
  } else {
    PrintF("AssembleArchBranch Unimplemented arch_opcode: %d\n",
           instr->arch_opcode());
    UNIMPLEMENTED();
  }
  if (!fallthru) __ Branch(flabel);  // no fallthru to flabel.
#undef __
#define __ masm()->
}

// Assembles branches after an instruction.
void CodeGenerator::AssembleArchBranch(Instruction* instr, BranchInfo* branch) {
  Label* tlabel = branch->true_label;
  Label* flabel = branch->false_label;

  AssembleBranchToLabels(this, masm(), instr, branch->condition, tlabel, flabel,
                         branch->fallthru);
}

void CodeGenerator::AssembleArchConditionalBranch(Instruction* instr,
                                                  BranchInfo* branch) {
  UNREACHABLE();
}

#undef UNSUPPORTED_COND

void CodeGenerator::AssembleArchDeoptBranch(Instruction* instr,
                                            BranchInfo* branch) {
  AssembleArchBranch(instr, branch);
}

void CodeGenerator::AssembleArchJumpRegardlessOfAssemblyOrder(
    RpoNumber target) {
  __ Branch(GetLabel(target));
}

#if V8_ENABLE_WEBASSEMBLY
void CodeGenerator::AssembleArchTrap(Instruction* instr,
                                     FlagsCondition condition) {
  auto ool = zone()->New<WasmOutOfLineTrap>(this, instr);
  Label* tlabel = ool->entry();
  AssembleBranchToLabels(this, masm(), instr, condition, tlabel, nullptr, true);
}
#endif  // V8_ENABLE_WEBASSEMBLY

// Assembles boolean materializations after an instruction.
void CodeGenerator::AssembleArchBoolean(Instruction* instr,
                                        FlagsCondition condition) {
  Loong64OperandConverter i(this, instr);

  // Materialize a full 32-bit 1 or 0 value. The result register is always the
  // last output of the instruction.
  DCHECK_NE(0u, instr->OutputCount());
  Register result = i.OutputRegister(instr->OutputCount() - 1);
  // Loong64 does not have condition code flags, so compare and branch are
  // implemented differently than on the other arch's. The compare operations
  // emit loong64 pseudo-instructions, which are checked and handled here.

  if (instr->arch_opcode() == kLoong64Tst) {
    Condition cc = FlagsConditionToConditionTst(condition);
    if (cc == eq) {
      __ Sltu(result, t8, 1);
    } else {
      __ Sltu(result, zero_reg, t8);
    }
    return;
  } else if (instr->arch_opcode() == kLoong64Add_d ||
             instr->arch_opcode() == kLoong64Sub_d) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    Condition cc = FlagsConditionToConditionOvf(condition);
    // Check for overflow creates 1 or 0 for result.
    __ srli_d(scratch, i.OutputRegister(), 63);
    __ srli_w(result, i.OutputRegister(), 31);
    __ xor_(result, scratch, result);
    if (cc == eq)  // Toggle result for not overflow.
      __ xori(result, result, 1);
    return;
  } else if (instr->arch_opcode() == kLoong64AddOvf_d ||
             instr->arch_opcode() == kLoong64SubOvf_d) {
    // Overflow occurs if overflow register is negative
    __ slt(result, t8, zero_reg);
  } else if (instr->arch_opcode() == kLoong64MulOvf_w ||
             instr->arch_opcode() == kLoong64MulOvf_d) {
    // Overflow occurs if overflow register is not zero
    __ Sgtu(result, t8, zero_reg);
  } else if (instr->arch_opcode() == kLoong64Cmp32 ||
             instr->arch_opcode() == kLoong64Cmp64) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    Register left = i.InputRegister(0);
    Operand right = i.InputOperand(1);
    if (COMPRESS_POINTERS_BOOL && (instr->arch_opcode() == kLoong64Cmp32)) {
      Register temp0 = i.TempRegister(0);
      Register temp1 = right.is_reg() ? i.TempRegister(1) : no_reg;
      SignExtend(masm(), instr, &left, &right, &temp0, &temp1);
    }
    __ CompareWord(cc, result, left, right);
    return;
  } else if (instr->arch_opcode() == kLoong64Float64Cmp ||
             instr->arch_opcode() == kLoong64Float32Cmp) {
    FPURegister left = i.InputOrZeroDoubleRegister(0);
    FPURegister right = i.InputOrZeroDoubleRegister(1);
    if ((left == kDoubleRegZero || right == kDoubleRegZero) &&
        !__ IsDoubleZeroRegSet()) {
      __ Move(kDoubleRegZero, 0.0);
    }
    bool predicate;
    FlagsConditionToConditionCmpFPU(&predicate, condition);
    {
      __ movcf2gr(result, FCC0);
      if (!predicate) {
        __ xori(result, result, 1);
      }
    }
    return;
  } else if (instr->arch_opcode() == kArchStackPointerGreaterThan) {
    Condition cc = FlagsConditionToConditionCmp(condition);
    DCHECK((cc == ls) || (cc == hi));
    if (cc == ls) {
      __ xori(i.OutputRegister(), i.TempRegister(0), 1);
    }
    return;
  } else {
    PrintF("AssembleArchBranch Unimplemented arch_opcode is : %d\n",
           instr->arch_opcode());
    TRACE("UNIMPLEMENTED code_generator_loong64: %s at line %d\n", __FUNCTION__,
          __LINE__);
    UNIMPLEMENTED();
  }
}

void CodeGenerator::AssembleArchConditionalBoolean(Instruction* instr) {
  UNREACHABLE();
}

void CodeGenerator::AssembleArchBinarySearchSwitch(Instruction* instr) {
  Loong64OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  std::vector<std::pair<int32_t, Label*>> cases;
  for (size_t index = 2; index < instr->InputCount(); index += 2) {
    cases.push_back({i.InputInt32(index + 0), GetLabel(i.InputRpo(index + 1))});
  }

  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  // The input register may contains dirty data in upper 32 bits, explicitly
  // sign-extend it here.
  __ slli_w(scratch, input, 0);
  AssembleArchBinarySearchSwitchRange(scratch, i.InputRpo(1), cases.data(),
                                      cases.data() + cases.size());
}

void CodeGenerator::AssembleArchTableSwitch(Instruction* instr) {
  Loong64OperandConverter i(this, instr);
  Register input = i.InputRegister(0);
  size_t const case_count = instr->InputCount() - 2;

  UseScratchRegisterScope temps(masm());
  Register scratch = temps.Acquire();
  // The input register may contains dirty data in upper 32 bits, explicitly
  // sign-extend it here.
  __ slli_w(scratch, input, 0);
  __ Branch(GetLabel(i.InputRpo(1)), hs, scratch, Operand(case_count));
  __ GenerateSwitchTable(scratch, case_count, [&i, this](size_t index) {
    return GetLabel(i.InputRpo(index + 2));
  });
}

void CodeGenerator::AssembleArchSelect(Instruction* instr,
                                       FlagsCondition condition) {
  UNIMPLEMENTED();
}

void CodeGenerator::FinishFrame(Frame* frame) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    int count = saves_fpu.Count();
    DCHECK_EQ(kNumCalleeSavedFPU, count);
    frame->AllocateSavedCalleeRegisterSlots(count *
                                            (kDoubleSize / kSystemPointerSize));
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    int count = saves.Count();
    frame->AllocateSavedCalleeRegisterSlots(count);
  }
}

void CodeGenerator::AssembleConstructFrame() {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  if (frame_access_state()->has_frame()) {
    if (call_descriptor->IsCFunctionCall()) {
#if V8_ENABLE_WEBASSEMBLY
      if (info()->GetOutputStackFrameType() == StackFrame::C_WASM_ENTRY) {
        __ StubPrologue(StackFrame::C_WASM_ENTRY);
        // Reserve stack space for saving the c_entry_fp later.
        __ Sub_d(sp, sp, Operand(kSystemPointerSize));
#else
      // For balance.
      if (false) {
#endif  // V8_ENABLE_WEBASSEMBLY
      } else {
        __ Push(ra, fp);
        __ mov(fp, sp);
      }
    } else if (call_descriptor->IsJSFunctionCall()) {
      __ Prologue();
    } else {
      __ StubPrologue(info()->GetOutputStackFrameType());
#if V8_ENABLE_WEBASSEMBLY
      if (call_descriptor->IsWasmFunctionCall() ||
          call_descriptor->IsWasmImportWrapper() ||
          call_descriptor->IsWasmCapiFunction()) {
        // For import wrappers and C-API functions, this stack slot is only used
        // for printing stack traces in V8. Also, it holds a WasmImportData
        // instead of the trusted instance data, which is taken care of in the
        // frames accessors.
        __ Push(kWasmImplicitArgRegister);
      }
      if (call_descriptor->IsWasmCapiFunction()) {
        // Reserve space for saving the PC later.
        __ Sub_d(sp, sp, Operand(kSystemPointerSize));
      }
#endif  // V8_ENABLE_WEBASSEMBLY
    }
  }

  int required_slots =
      frame()->GetTotalFrameSlotCount() - frame()->GetFixedSlotCount();

  if (info()->is_osr()) {
    // TurboFan OSR-compiled functions cannot be entered directly.
    __ Abort(AbortReason::kShouldNotDirectlyEnterOsrFunction);

    // Unoptimized code jumps directly to this entrypoint while the unoptimized
    // frame is still on the stack. Optimized code uses OSR values directly from
    // the unoptimized frame. Thus, all that needs to be done is to allocate the
    // remaining stack slots.
    __ RecordComment("-- OSR entrypoint --");
    osr_pc_offset_ = __ pc_offset();
    required_slots -= osr_helper()->UnoptimizedFrameSlots();
  }

  const RegList saves = call_descriptor->CalleeSavedRegisters();
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();

  if (required_slots > 0) {
    DCHECK(frame_access_state()->has_frame());
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
        Register stack_limit = temps.Acquire();
        __ LoadStackLimit(stack_limit,
                          MacroAssembler::StackLimitKind::kRealStackLimit);
        __ Add_d(stack_limit, stack_limit,
                 Operand(required_slots * kSystemPointerSize));
        __ Branch(&done, uge, sp, Operand(stack_limit));
      }

      if (v8_flags.experimental_wasm_growable_stacks) {
        RegList regs_to_save;
        regs_to_save.set(WasmHandleStackOverflowDescriptor::GapRegister());
        regs_to_save.set(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister());

        for (auto reg : wasm::kGpParamRegisters) regs_to_save.set(reg);
        __ MultiPush(regs_to_save);
        __ li(WasmHandleStackOverflowDescriptor::GapRegister(),
              required_slots * kSystemPointerSize);
        __ Add_d(
            WasmHandleStackOverflowDescriptor::FrameBaseRegister(), fp,
            Operand(call_descriptor->ParameterSlotCount() * kSystemPointerSize +
                    CommonFrameConstants::kFixedFrameSizeAboveFp));
        __ CallBuiltin(Builtin::kWasmHandleStackOverflow);
        __ MultiPop(regs_to_save);
      } else {
        __ Call(static_cast<intptr_t>(Builtin::kWasmStackOverflow),
                RelocInfo::WASM_STUB_CALL);
        // The call does not return, hence we can ignore any references and just
        // define an empty safepoint.
        ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
        RecordSafepoint(reference_map);
        if (v8_flags.debug_code) {
          __ stop();
        }
      }

      __ bind(&done);
    }
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  const int returns = frame()->GetReturnSlotCount();

  // Skip callee-saved and return slots, which are pushed below.
  required_slots -= saves.Count();
  required_slots -= saves_fpu.Count();
  required_slots -= returns;
  if (required_slots > 0) {
    __ Sub_d(sp, sp, Operand(required_slots * kSystemPointerSize));
  }

  if (!saves_fpu.is_empty()) {
    // Save callee-saved FPU registers.
    __ MultiPushFPU(saves_fpu);
    DCHECK_EQ(kNumCalleeSavedFPU, saves_fpu.Count());
  }

  if (!saves.is_empty()) {
    // Save callee-saved registers.
    __ MultiPush(saves);
  }

  if (returns != 0) {
    // Create space for returns.
    __ Sub_d(sp, sp, Operand(returns * kSystemPointerSize));
  }

  for (int spill_slot : frame()->tagged_slots()) {
    FrameOffset offset = frame_access_state()->GetFrameOffset(spill_slot);
    DCHECK(offset.from_frame_pointer());
    __ St_d(zero_reg, MemOperand(fp, offset.offset()));
  }
}

void CodeGenerator::AssembleReturn(InstructionOperand* additional_pop_count) {
  auto call_descriptor = linkage()->GetIncomingDescriptor();

  const int returns = frame()->GetReturnSlotCount();
  if (returns != 0) {
    __ Add_d(sp, sp, Operand(returns * kSystemPointerSize));
  }

  // Restore GP registers.
  const RegList saves = call_descriptor->CalleeSavedRegisters();
  if (!saves.is_empty()) {
    __ MultiPop(saves);
  }

  // Restore FPU registers.
  const DoubleRegList saves_fpu = call_descriptor->CalleeSavedFPRegisters();
  if (!saves_fpu.is_empty()) {
    __ MultiPopFPU(saves_fpu);
  }

  Loong64OperandConverter g(this, nullptr);

  const int parameter_slots =
      static_cast<int>(call_descriptor->ParameterSlotCount());

  // {aditional_pop_count} is only greater than zero if {parameter_slots = 0}.
  // Check RawMachineAssembler::PopAndReturn.
  if (parameter_slots != 0) {
    if (additional_pop_count->IsImmediate()) {
      DCHECK_EQ(g.ToConstant(additional_pop_count).ToInt32(), 0);
    } else if (v8_flags.debug_code) {
      __ Assert(eq, AbortReason::kUnexpectedAdditionalPopValue,
                g.ToRegister(additional_pop_count),
                Operand(static_cast<int64_t>(0)));
    }
  }

#if V8_ENABLE_WEBASSEMBLY
  if (call_descriptor->IsWasmFunctionCall() &&
      v8_flags.experimental_wasm_growable_stacks) {
    Label done;
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.Acquire();
      __ Ld_d(scratch, MemOperand(fp, TypedFrameConstants::kFrameTypeOffset));
      __ BranchShort(
          &done, ne, scratch,
          Operand(StackFrame::TypeToMarker(StackFrame::WASM_SEGMENT_START)));
    }
    RegList regs_to_save;
    for (auto reg : wasm::kGpReturnRegisters) regs_to_save.set(reg);
    __ MultiPush(regs_to_save);
    __ li(kCArgRegs[0], ExternalReference::isolate_address());
    {
      UseScratchRegisterScope temps{masm()};
      Register scratch = temps.Acquire();
      __ PrepareCallCFunction(1, scratch);
    }
    __ CallCFunction(ExternalReference::wasm_shrink_stack(), 1);
    __ mov(fp, kReturnRegister0);
    __ MultiPop(regs_to_save);
    __ bind(&done);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  // Functions with JS linkage have at least one parameter (the receiver).
  // If {parameter_slots} == 0, it means it is a builtin with
  // kDontAdaptArgumentsSentinel, which takes care of JS arguments popping
  // itself.
  const bool drop_jsargs = frame_access_state()->has_frame() &&
                           call_descriptor->IsJSFunctionCall() &&
                           parameter_slots != 0;

  if (call_descriptor->IsCFunctionCall()) {
    AssembleDeconstructFrame();
  } else if (frame_access_state()->has_frame()) {
    // Canonicalize JSFunction return sites for now unless they have an variable
    // number of stack slot pops.
    if (additional_pop_count->IsImmediate() &&
        g.ToConstant(additional_pop_count).ToInt32() == 0) {
      if (return_label_.is_bound()) {
        __ Branch(&return_label_);
        return;
      } else {
        __ bind(&return_label_);
      }
    }
    if (drop_jsargs) {
      // Get the actual argument count
      __ Ld_d(t0, MemOperand(fp, StandardFrameConstants::kArgCOffset));
    }
    AssembleDeconstructFrame();
  }
  if (drop_jsargs) {
    // We must pop all arguments from the stack (including the receiver). This
    // number of arguments is given by max(1 + argc_reg, parameter_count).
    if (parameter_slots > 1) {
      __ li(t1, parameter_slots);
      __ slt(t2, t0, t1);
      __ Movn(t0, t1, t2);
    }
    __ Alsl_d(sp, t0, sp, kSystemPointerSizeLog2);
  } else if (additional_pop_count->IsImmediate()) {
    int additional_count = g.ToConstant(additional_pop_count).ToInt32();
    __ Drop(parameter_slots + additional_count);
  } else {
    Register pop_reg = g.ToRegister(additional_pop_count);
    __ Drop(parameter_slots);
    __ Alsl_d(sp, pop_reg, sp, kSystemPointerSizeLog2);
  }
  __ Ret();
}

void CodeGenerator::FinishCode() {}

void CodeGenerator::PrepareForDeoptimizationExits(
    ZoneDeque<DeoptimizationExit*>* exits) {}

AllocatedOperand CodeGenerator::Push(InstructionOperand* source) {
  auto rep = LocationOperand::cast(source)->representation();
  int new_slots = ElementSizeInPointers(rep);
  Loong64OperandConverter g(this, nullptr);
  int last_frame_slot_id =
      frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
  int sp_delta = frame_access_state_->sp_delta();
  int slot_id = last_frame_slot_id + sp_delta + new_slots;
  AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
  if (source->IsRegister()) {
    __ Push(g.ToRegister(source));
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else if (source->IsStackSlot()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Ld_d(scratch, g.ToMemOperand(source));
    __ Push(scratch);
    frame_access_state()->IncreaseSPDelta(new_slots);
  } else {
    // No push instruction for this operand type. Bump the stack pointer and
    // assemble the move.
    __ Sub_d(sp, sp, Operand(new_slots * kSystemPointerSize));
    frame_access_state()->IncreaseSPDelta(new_slots);
    AssembleMove(source, &stack_slot);
  }
  temp_slots_ += new_slots;
  return stack_slot;
}

void CodeGenerator::Pop(InstructionOperand* dest, MachineRepresentation rep) {
  Loong64OperandConverter g(this, nullptr);
  int dropped_slots = ElementSizeInPointers(rep);
  if (dest->IsRegister()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Pop(g.ToRegister(dest));
  } else if (dest->IsStackSlot()) {
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    __ Pop(scratch);
    __ St_d(scratch, g.ToMemOperand(dest));
  } else {
    int last_frame_slot_id =
        frame_access_state_->frame()->GetTotalFrameSlotCount() - 1;
    int sp_delta = frame_access_state_->sp_delta();
    int slot_id = last_frame_slot_id + sp_delta;
    AllocatedOperand stack_slot(LocationOperand::STACK_SLOT, rep, slot_id);
    AssembleMove(&stack_slot, dest);
    frame_access_state()->IncreaseSPDelta(-dropped_slots);
    __ Add_d(sp, sp, Operand(dropped_slots * kSystemPointerSize));
  }
  temp_slots_ -= dropped_slots;
}

void CodeGenerator::PopTempStackSlots() {
  if (temp_slots_ > 0) {
    frame_access_state()->IncreaseSPDelta(-temp_slots_);
    __ Add_d(sp, sp, Operand(temp_slots_ * kSystemPointerSize));
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
  temps.Exclude(move_cycle_.scratch_regs);
  temps.ExcludeFp(move_cycle_.scratch_fpregs);
  if (!IsFloatingPoint(rep)) {
    if (temps.hasAvailable()) {
      Register scratch = move_cycle_.temps->Acquire();
      move_cycle_.scratch_reg.emplace(scratch);
    } else if (temps.hasAvailableFp()) {
      // Try to use an FP register if no GP register is available for non-FP
      // moves.
      FPURegister scratch = move_cycle_.temps->AcquireFp();
      move_cycle_.scratch_fpreg.emplace(scratch);
    }
  } else {
    DCHECK(temps.hasAvailableFp());
    FPURegister scratch = move_cycle_.temps->AcquireFp();
    move_cycle_.scratch_fpreg.emplace(scratch);
  }
  temps.Include(move_cycle_.scratch_regs);
  temps.IncludeFp(move_cycle_.scratch_fpregs);
  if (move_cycle_.scratch_reg.has_value()) {
    // A scratch register is available for this rep.
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(source, &scratch);
  } else if (move_cycle_.scratch_fpreg.has_value()) {
    // A scratch fp register is available for this rep.
    if (!IsFloatingPoint(rep)) {
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat64,
                               move_cycle_.scratch_fpreg->code());
      Loong64OperandConverter g(this, nullptr);
      if (source->IsStackSlot()) {
        __ Fld_d(g.ToDoubleRegister(&scratch), g.ToMemOperand(source));
      } else {
        DCHECK(source->IsRegister());
        __ movgr2fr_d(g.ToDoubleRegister(&scratch), g.ToRegister(source));
      }
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                               move_cycle_.scratch_fpreg->code());
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
    AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                             move_cycle_.scratch_reg->code());
    AssembleMove(&scratch, dest);
  } else if (move_cycle_.scratch_fpreg.has_value()) {
    if (!IsFloatingPoint(rep)) {
      // We used a DoubleRegister to move a non-FP operand, change the
      // representation to correctly interpret the InstructionOperand's code.
      AllocatedOperand scratch(LocationOperand::REGISTER,
                               MachineRepresentation::kFloat64,
                               move_cycle_.scratch_fpreg->code());
      Loong64OperandConverter g(this, nullptr);
      if (dest->IsStackSlot()) {
        __ Fst_d(g.ToDoubleRegister(&scratch), g.ToMemOperand(dest));
      } else {
        DCHECK(dest->IsRegister());
        __ movfr2gr_d(g.ToRegister(dest), g.ToDoubleRegister(&scratch));
      }
    } else {
      AllocatedOperand scratch(LocationOperand::REGISTER, rep,
                               move_cycle_.scratch_fpreg->code());
      AssembleMove(&scratch, dest);
    }
  } else {
    Pop(dest, rep);
  }
  // Restore the default state to release the {UseScratchRegisterScope} and to
  // prepare for the next cycle.
  move_cycle_ = MoveCycleState();
}

void CodeGenerator::SetPendingMove(MoveOperands* move) {
  InstructionOperand* src = &move->source();
  InstructionOperand* dst = &move->destination();
  UseScratchRegisterScope temps(masm());
  if (src->IsConstant() || (src->IsStackSlot() && dst->IsStackSlot())) {
    Register temp = temps.Acquire();
    move_cycle_.scratch_regs.set(temp);
  }
  if (src->IsAnyStackSlot() || dst->IsAnyStackSlot()) {
    Loong64OperandConverter g(this, nullptr);
    bool src_need_scratch = false;
    bool dst_need_scratch = false;
    if (src->IsStackSlot()) {
      // Doubleword load/store
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch =
          (!is_int16(src_mem.offset()) || (src_mem.offset() & 0b11) != 0) &&
          (!is_int12(src_mem.offset()) && !src_mem.hasIndexReg());
    } else if (src->IsFPStackSlot()) {
      // DoubleWord float-pointing load/store.
      MemOperand src_mem = g.ToMemOperand(src);
      src_need_scratch = !is_int12(src_mem.offset()) && !src_mem.hasIndexReg();
    }
    if (dst->IsStackSlot()) {
      // Doubleword load/store
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch =
          (!is_int16(dst_mem.offset()) || (dst_mem.offset() & 0b11) != 0) &&
          (!is_int12(dst_mem.offset()) && !dst_mem.hasIndexReg());
    } else if (dst->IsFPStackSlot()) {
      // DoubleWord float-pointing load/store.
      MemOperand dst_mem = g.ToMemOperand(dst);
      dst_need_scratch = !is_int12(dst_mem.offset()) && !dst_mem.hasIndexReg();
    }
    if (src_need_scratch || dst_need_scratch) {
      Register temp = temps.Acquire();
      move_cycle_.scratch_regs.set(temp);
    }
  }
}

namespace {

bool Is32BitOperand(InstructionOperand* operand) {
  DCHECK(operand->IsStackSlot() || operand->IsRegister());
  MachineRepresentation mr = LocationOperand::cast(operand)->representation();
  return mr == MachineRepresentation::kWord32 ||
         mr == MachineRepresentation::kCompressed ||
         mr == MachineRepresentation::kCompressedPointer;
}

// When we need only 32 bits, move only 32 bits, otherwise the destination
// register' upper 32 bits may contain dirty data.
bool Use32BitMove(InstructionOperand* source, InstructionOperand* destination) {
  return Is32BitOperand(source) && Is32BitOperand(destination);
}

}  // namespace

void CodeGenerator::AssembleMove(InstructionOperand* source,
                                 InstructionOperand* destination) {
  Loong64OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      __ mov(g.ToRegister(destination), src);
    } else {
      __ St_d(src, g.ToMemOperand(destination));
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsRegister() || destination->IsStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsRegister()) {
      if (Use32BitMove(source, destination)) {
        __ Ld_w(g.ToRegister(destination), src);
      } else {
        __ Ld_d(g.ToRegister(destination), src);
      }
    } else {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      __ Ld_d(scratch, src);
      __ St_d(scratch, g.ToMemOperand(destination));
    }
  } else if (source->IsConstant()) {
    Constant src = g.ToConstant(source);
    if (destination->IsRegister() || destination->IsStackSlot()) {
      UseScratchRegisterScope temps(masm());
      Register scratch = temps.Acquire();
      Register dst =
          destination->IsRegister() ? g.ToRegister(destination) : scratch;
      switch (src.type()) {
        case Constant::kInt32:
          __ li(dst, Operand(src.ToInt32(), src.rmode()));
          break;
        case Constant::kFloat32:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat32()));
          break;
        case Constant::kInt64:
          __ li(dst, Operand(src.ToInt64(), src.rmode()));
          break;
        case Constant::kFloat64:
          __ li(dst, Operand::EmbeddedNumber(src.ToFloat64().value()));
          break;
        case Constant::kExternalReference:
          __ li(dst, src.ToExternalReference());
          break;
        case Constant::kHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadRoot(dst, index);
          } else {
            __ li(dst, src_object);
          }
          break;
        }
        case Constant::kCompressedHeapObject: {
          Handle<HeapObject> src_object = src.ToHeapObject();
          RootIndex index;
          if (IsMaterializableFromRoot(src_object, &index)) {
            __ LoadTaggedRoot(dst, index);
          } else {
            __ li(dst, src_object, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
          }
          break;
        }
        case Constant::kRpoNumber:
          UNREACHABLE();  // TODO(titzer): loading RPO numbers on LOONG64.
      }
      if (destination->IsStackSlot()) __ St_d(dst, g.ToMemOperand(destination));
    } else if (src.type() == Constant::kFloat32) {
      if (destination->IsFPStackSlot()) {
        MemOperand dst = g.ToMemOperand(destination);
        if (base::bit_cast<int32_t>(src.ToFloat32()) == 0) {
          __ St_d(zero_reg, dst);
        } else {
          UseScratchRegisterScope temps(masm());
          Register scratch = temps.Acquire();
          __ li(scratch, Operand(base::bit_cast<int32_t>(src.ToFloat32())));
          __ St_d(scratch, dst);
        }
      } else {
        DCHECK(destination->IsFPRegister());
        FloatRegister dst = g.ToSingleRegister(destination);
        __ Move(dst, src.ToFloat32());
      }
    } else {
      DCHECK_EQ(Constant::kFloat64, src.type());
      DoubleRegister dst = destination->IsFPRegister()
                               ? g.ToDoubleRegister(destination)
                               : kScratchDoubleReg;
      __ Move(dst, src.ToFloat64().value());
      if (destination->IsFPStackSlot()) {
        __ Fst_d(dst, g.ToMemOperand(destination));
      }
    }
  } else if (source->IsFPRegister()) {
    FPURegister src = g.ToDoubleRegister(source);
    if (destination->IsFPRegister()) {
      FPURegister dst = g.ToDoubleRegister(destination);
      __ Move(dst, src);
    } else {
      DCHECK(destination->IsFPStackSlot());
      __ Fst_d(src, g.ToMemOperand(destination));
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPRegister() || destination->IsFPStackSlot());
    MemOperand src = g.ToMemOperand(source);
    if (destination->IsFPRegister()) {
      __ Fld_d(g.ToDoubleRegister(destination), src);
    } else {
      DCHECK(destination->IsFPStackSlot());
      FPURegister temp = kScratchDoubleReg;
      __ Fld_d(temp, src);
      __ Fst_d(temp, g.ToMemOperand(destination));
    }
  } else {
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleSwap(InstructionOperand* source,
                                 InstructionOperand* destination) {
  Loong64OperandConverter g(this, nullptr);
  // Dispatch on the source and destination operand kinds.  Not all
  // combinations are possible.
  if (source->IsRegister()) {
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    // Register-register.
    Register src = g.ToRegister(source);
    if (destination->IsRegister()) {
      Register dst = g.ToRegister(destination);
      __ Move(scratch, src);
      __ Move(src, dst);
      __ Move(dst, scratch);
    } else {
      DCHECK(destination->IsStackSlot());
      MemOperand dst = g.ToMemOperand(destination);
      __ mov(scratch, src);
      __ Ld_d(src, dst);
      __ St_d(scratch, dst);
    }
  } else if (source->IsStackSlot()) {
    DCHECK(destination->IsStackSlot());
    // TODO(LOONG_dev): LOONG64 Optimize scratch registers usage
    // Since the Ld instruction may need a scratch reg,
    // we should not use both of the two scratch registers in
    // UseScratchRegisterScope here.
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    FPURegister scratch_d = kScratchDoubleReg;
    MemOperand src = g.ToMemOperand(source);
    MemOperand dst = g.ToMemOperand(destination);
    __ Ld_d(scratch, src);
    __ Fld_d(scratch_d, dst);
    __ St_d(scratch, dst);
    __ Fst_d(scratch_d, src);
  } else if (source->IsFPRegister()) {
    FPURegister scratch_d = kScratchDoubleReg;
    FPURegister src = g.ToDoubleRegister(source);
    if (destination->IsFPRegister()) {
      FPURegister dst = g.ToDoubleRegister(destination);
      __ Move(scratch_d, src);
      __ Move(src, dst);
      __ Move(dst, scratch_d);
    } else {
      DCHECK(destination->IsFPStackSlot());
      MemOperand dst = g.ToMemOperand(destination);
      __ Move(scratch_d, src);
      __ Fld_d(src, dst);
      __ Fst_d(scratch_d, dst);
    }
  } else if (source->IsFPStackSlot()) {
    DCHECK(destination->IsFPStackSlot());
    UseScratchRegisterScope temps(masm());
    Register scratch = temps.Acquire();
    FPURegister scratch_d = kScratchDoubleReg;
    MemOperand src = g.ToMemOperand(source);
    MemOperand dst = g.ToMemOperand(destination);
    __ Fld_d(scratch_d, src);
    __ Ld_d(scratch, dst);
    __ Fst_d(scratch_d, dst);
    __ St_d(scratch, src);
  } else {
    // No other combinations are possible.
    UNREACHABLE();
  }
}

void CodeGenerator::AssembleJumpTable(base::Vector<Label*> targets) {
  // On 64-bit LOONG64 we emit the jump tables inline.
  UNREACHABLE();
}

#undef ASSEMBLE_ATOMIC_LOAD_INTEGER
#undef ASSEMBLE_ATOMIC_STORE_INTEGER
#undef ASSEMBLE_ATOMIC_BINOP
#undef ASSEMBLE_ATOMIC_BINOP_EXT
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER
#undef ASSEMBLE_ATOMIC_COMPARE_EXCHANGE_INTEGER_EXT
#undef ASSEMBLE_IEEE754_BINOP
#undef ASSEMBLE_IEEE754_UNOP

#undef TRACE
#undef __

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```