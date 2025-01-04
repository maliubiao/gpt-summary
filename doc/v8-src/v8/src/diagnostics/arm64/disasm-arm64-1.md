Response: The user wants a summary of the provided C++ code, which is part of the V8 JavaScript engine. This is the second part of the file. I need to explain what the code does and if it's related to JavaScript, providing a JavaScript example if applicable.

Based on the code snippets, it seems this part focuses on disassembling ARM64 NEON (Advanced SIMD) instructions. The functions `VisitNEON...` are responsible for recognizing different NEON instruction patterns and formatting them into human-readable assembly code.

The code iterates through various NEON instruction types like `NEONExtract`, `NEONLoadStoreMultiStruct`, `NEONLoadStoreSingleStruct`, `NEONModifiedImmediate`, `NEONPerm`, `NEONScalar...`, `NEONShiftImmediate`, `NEONTable`, and others. For each type, it determines the corresponding assembly mnemonic (e.g., "ext", "ld1", "st1", "movi") and the format of its operands.

The code also handles cases where an instruction encoding is "unallocated" or "unimplemented," indicating invalid or unsupported instructions.

The `DisassemblingDecoder` class appears to be the core component responsible for this process. It uses helper classes like `NEONFormatDecoder` to manage the formatting of NEON-specific operands.

The later part of the code defines a `PrintDisassembler` which inherits from `DisassemblingDecoder` and outputs the disassembled instructions to a file stream. There's also a `BufferDisassembler` for writing the disassembled output to a buffer.

The `Disassembler` class provides the main interface for disassembling instructions.

**Relationship to JavaScript:**

This code is part of the V8 engine, which executes JavaScript. When JavaScript code is compiled, the V8 engine generates machine code, which includes ARM64 instructions when running on an ARM64 architecture. The NEON instructions are often used for optimizing operations on arrays and other data structures, which are common in JavaScript. The disassembler functionality is useful for debugging and understanding the generated machine code.

**JavaScript Example:**

While this C++ code doesn't directly *execute* JavaScript, it helps in understanding how certain JavaScript operations might be translated into NEON instructions. For example, consider a JavaScript array manipulation:

```javascript
const arr1 = [1, 2, 3, 4];
const arr2 = [5, 6, 7, 8];
const result = arr1.map((x, i) => x + arr2[i]);
```

On an ARM64 architecture, the V8 engine might use NEON instructions to perform the element-wise addition in the `map` function efficiently. The `VisitNEONLoadStoreMultiStruct` functions, for example, could be involved in loading chunks of `arr1` and `arr2` into NEON registers, and other NEON arithmetic instructions would perform the addition. The disassembler code would then be used to inspect the generated NEON assembly instructions.
This C++ code file, `disasm-arm64.cc`, which is part of the V8 JavaScript engine, is responsible for **disassembling ARM64 instructions, specifically focusing on NEON (Advanced SIMD) instructions**. It takes raw instruction bits and translates them into a human-readable assembly language representation.

Here's a breakdown of its functionality:

* **Instruction Visitation:** The code defines a `DisassemblingDecoder` class with a series of `Visit...` methods. Each `Visit` method corresponds to a specific category or type of ARM64 instruction, particularly those belonging to the NEON instruction set.
* **NEON Instruction Decoding:**  The `VisitNEON...` methods analyze the bit patterns of NEON instructions to identify the specific operation and its operands (registers, immediate values, etc.).
* **Mnemonic and Format Generation:** For each recognized NEON instruction, the code determines the correct assembly mnemonic (e.g., `ld1`, `st1`, `add`, `mul`) and the appropriate format string to represent the operands. It uses helper classes like `NEONFormatDecoder` to handle the specifics of NEON operand formatting.
* **Handling Unimplemented and Unallocated Instructions:** The code explicitly handles cases where an instruction encoding is not valid or not yet implemented, assigning the mnemonics "unimplemented" or "unallocated".
* **Output Formatting:** The `Format` method takes the instruction, mnemonic, and format string to produce the final assembly output. It uses the `Substitute` method to replace placeholders in the format string with the actual operand values.
* **Register Name Handling:** The `AppendRegisterNameToOutput` function correctly formats the names of ARM64 registers (both general-purpose and NEON vector registers). It handles special cases like the stack pointer (`sp`) and the zero register (`xzr`).
* **Immediate Value Handling:**  The code includes logic in `SubstituteImmediateField` to correctly format various types of immediate values used in ARM64 instructions, including those specific to NEON.
* **Disassembler Class:** The `Disassembler` class provides the main entry point for disassembling instructions. It uses the `DisassemblingDecoder` to perform the core decoding and formatting.
* **Output to Stream or Buffer:** The code provides two concrete implementations of the disassembler: `PrintDisassembler` which outputs the disassembled instructions to a file stream, and `BufferDisassembler` which writes the output to a character buffer.

**Relationship to JavaScript and JavaScript Example:**

This code is crucial for understanding how the V8 engine executes JavaScript code on ARM64 architectures. When JavaScript code is compiled by V8, it is translated into machine code, which includes ARM64 instructions. NEON instructions are particularly important for optimizing operations on arrays and other data-parallel tasks common in JavaScript.

While this C++ code itself doesn't directly execute JavaScript, it allows developers and researchers to inspect the generated ARM64 code, including the NEON instructions, to understand performance characteristics and debug potential issues.

Here's how this code relates to JavaScript conceptually:

Imagine a simple JavaScript array addition:

```javascript
const arr1 = [1, 2, 3, 4];
const arr2 = [5, 6, 7, 8];
const result = arr1.map((x, i) => x + arr2[i]);
```

When V8 compiles this JavaScript code on an ARM64 system, it might generate NEON instructions to perform the element-wise addition in parallel. The `VisitNEONLoadStoreMultiStruct` functions could be responsible for loading chunks of `arr1` and `arr2` into NEON registers, and then a NEON addition instruction (which would be handled by one of the `VisitNEON...` methods) would perform the parallel addition.

If you were to use a debugger or a V8 internal tool to inspect the generated machine code for this JavaScript snippet, the functions in `disasm-arm64.cc` would be used to translate the raw NEON instruction bytes into readable assembly like:

```assembly
ld1 {v0.s, v1.s, v2.s, v3.s}, [x0]  // Load elements of arr1
ld1 {v4.s, v5.s, v6.s, v7.s}, [x1]  // Load elements of arr2
add v8.4s, v0.4s, v4.4s              // Add corresponding elements using NEON
st1 {v8.s, v9.s, v10.s, v11.s}, [x2] // Store the result
```

The `disasm-arm64.cc` code provides the logic to generate this kind of assembly output from the raw instruction bytes. It defines how `ld1`, `add`, `st1`, and the register names like `v0.s` are derived from the binary representation of the NEON instructions.

Prompt: 
```
这是目录为v8/src/diagnostics/arm64/disasm-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
assemblingDecoder::VisitNEONExtract(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(NEONExtract)";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LogicalFormatMap());
  if (instr->Mask(NEONExtractMask) == NEON_EXT) {
    mnemonic = "ext";
    form = "'Vd.%s, 'Vn.%s, 'Vm.%s, 'IVExtract";
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONLoadStoreMultiStruct(Instruction* instr) {
  const char* mnemonic = nullptr;
  const char* form = nullptr;
  const char* form_1v = "{'Vt.%s}, ['Xns]";
  const char* form_2v = "{'Vt.%s, 'Vt2.%s}, ['Xns]";
  const char* form_3v = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s}, ['Xns]";
  const char* form_4v = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s, 'Vt4.%s}, ['Xns]";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LoadStoreFormatMap());

  switch (instr->Mask(NEONLoadStoreMultiStructMask)) {
    case NEON_LD1_1v:
      mnemonic = "ld1";
      form = form_1v;
      break;
    case NEON_LD1_2v:
      mnemonic = "ld1";
      form = form_2v;
      break;
    case NEON_LD1_3v:
      mnemonic = "ld1";
      form = form_3v;
      break;
    case NEON_LD1_4v:
      mnemonic = "ld1";
      form = form_4v;
      break;
    case NEON_LD2:
      mnemonic = "ld2";
      form = form_2v;
      break;
    case NEON_LD3:
      mnemonic = "ld3";
      form = form_3v;
      break;
    case NEON_LD4:
      mnemonic = "ld4";
      form = form_4v;
      break;
    case NEON_ST1_1v:
      mnemonic = "st1";
      form = form_1v;
      break;
    case NEON_ST1_2v:
      mnemonic = "st1";
      form = form_2v;
      break;
    case NEON_ST1_3v:
      mnemonic = "st1";
      form = form_3v;
      break;
    case NEON_ST1_4v:
      mnemonic = "st1";
      form = form_4v;
      break;
    case NEON_ST2:
      mnemonic = "st2";
      form = form_2v;
      break;
    case NEON_ST3:
      mnemonic = "st3";
      form = form_3v;
      break;
    case NEON_ST4:
      mnemonic = "st4";
      form = form_4v;
      break;
    default:
      break;
  }

  // Work out unallocated encodings.
  bool allocated = (mnemonic != nullptr);
  switch (instr->Mask(NEONLoadStoreMultiStructMask)) {
    case NEON_LD2:
    case NEON_LD3:
    case NEON_LD4:
    case NEON_ST2:
    case NEON_ST3:
    case NEON_ST4:
      // LD[2-4] and ST[2-4] cannot use .1d format.
      allocated = (instr->NEONQ() != 0) || (instr->NEONLSSize() != 3);
      break;
    default:
      break;
  }
  if (allocated) {
    DCHECK_NOT_NULL(mnemonic);
    DCHECK_NOT_NULL(form);
  } else {
    mnemonic = "unallocated";
    form = "(NEONLoadStoreMultiStruct)";
  }

  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONLoadStoreMultiStructPostIndex(
    Instruction* instr) {
  const char* mnemonic = nullptr;
  const char* form = nullptr;
  const char* form_1v = "{'Vt.%s}, ['Xns], 'Xmr1";
  const char* form_2v = "{'Vt.%s, 'Vt2.%s}, ['Xns], 'Xmr2";
  const char* form_3v = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s}, ['Xns], 'Xmr3";
  const char* form_4v = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s, 'Vt4.%s}, ['Xns], 'Xmr4";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LoadStoreFormatMap());

  switch (instr->Mask(NEONLoadStoreMultiStructPostIndexMask)) {
    case NEON_LD1_1v_post:
      mnemonic = "ld1";
      form = form_1v;
      break;
    case NEON_LD1_2v_post:
      mnemonic = "ld1";
      form = form_2v;
      break;
    case NEON_LD1_3v_post:
      mnemonic = "ld1";
      form = form_3v;
      break;
    case NEON_LD1_4v_post:
      mnemonic = "ld1";
      form = form_4v;
      break;
    case NEON_LD2_post:
      mnemonic = "ld2";
      form = form_2v;
      break;
    case NEON_LD3_post:
      mnemonic = "ld3";
      form = form_3v;
      break;
    case NEON_LD4_post:
      mnemonic = "ld4";
      form = form_4v;
      break;
    case NEON_ST1_1v_post:
      mnemonic = "st1";
      form = form_1v;
      break;
    case NEON_ST1_2v_post:
      mnemonic = "st1";
      form = form_2v;
      break;
    case NEON_ST1_3v_post:
      mnemonic = "st1";
      form = form_3v;
      break;
    case NEON_ST1_4v_post:
      mnemonic = "st1";
      form = form_4v;
      break;
    case NEON_ST2_post:
      mnemonic = "st2";
      form = form_2v;
      break;
    case NEON_ST3_post:
      mnemonic = "st3";
      form = form_3v;
      break;
    case NEON_ST4_post:
      mnemonic = "st4";
      form = form_4v;
      break;
    default:
      break;
  }

  // Work out unallocated encodings.
  bool allocated = (mnemonic != nullptr);
  switch (instr->Mask(NEONLoadStoreMultiStructPostIndexMask)) {
    case NEON_LD2_post:
    case NEON_LD3_post:
    case NEON_LD4_post:
    case NEON_ST2_post:
    case NEON_ST3_post:
    case NEON_ST4_post:
      // LD[2-4] and ST[2-4] cannot use .1d format.
      allocated = (instr->NEONQ() != 0) || (instr->NEONLSSize() != 3);
      break;
    default:
      break;
  }
  if (allocated) {
    DCHECK_NOT_NULL(mnemonic);
    DCHECK_NOT_NULL(form);
  } else {
    mnemonic = "unallocated";
    form = "(NEONLoadStoreMultiStructPostIndex)";
  }

  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONLoadStoreSingleStruct(Instruction* instr) {
  const char* mnemonic = nullptr;
  const char* form = nullptr;

  const char* form_1b = "{'Vt.b}['IVLSLane0], ['Xns]";
  const char* form_1h = "{'Vt.h}['IVLSLane1], ['Xns]";
  const char* form_1s = "{'Vt.s}['IVLSLane2], ['Xns]";
  const char* form_1d = "{'Vt.d}['IVLSLane3], ['Xns]";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LoadStoreFormatMap());

  switch (instr->Mask(NEONLoadStoreSingleStructMask)) {
    case NEON_LD1_b:
      mnemonic = "ld1";
      form = form_1b;
      break;
    case NEON_LD1_h:
      mnemonic = "ld1";
      form = form_1h;
      break;
    case NEON_LD1_s:
      mnemonic = "ld1";
      static_assert((NEON_LD1_s | (1 << NEONLSSize_offset)) == NEON_LD1_d,
                    "LSB of size distinguishes S and D registers.");
      form = ((instr->NEONLSSize() & 1) == 0) ? form_1s : form_1d;
      break;
    case NEON_ST1_b:
      mnemonic = "st1";
      form = form_1b;
      break;
    case NEON_ST1_h:
      mnemonic = "st1";
      form = form_1h;
      break;
    case NEON_ST1_s:
      mnemonic = "st1";
      static_assert((NEON_ST1_s | (1 << NEONLSSize_offset)) == NEON_ST1_d,
                    "LSB of size distinguishes S and D registers.");
      form = ((instr->NEONLSSize() & 1) == 0) ? form_1s : form_1d;
      break;
    case NEON_LD1R:
      mnemonic = "ld1r";
      form = "{'Vt.%s}, ['Xns]";
      break;
    case NEON_LD2_b:
    case NEON_ST2_b:
      mnemonic = (instr->NEONLoad() == 1) ? "ld2" : "st2";
      form = "{'Vt.b, 'Vt2.b}['IVLSLane0], ['Xns]";
      break;
    case NEON_LD2_h:
    case NEON_ST2_h:
      mnemonic = (instr->NEONLoad() == 1) ? "ld2" : "st2";
      form = "{'Vt.h, 'Vt2.h}['IVLSLane1], ['Xns]";
      break;
    case NEON_LD2_s:
    case NEON_ST2_s:
      static_assert((NEON_ST2_s | (1 << NEONLSSize_offset)) == NEON_ST2_d,
                    "LSB of size distinguishes S and D registers.");
      static_assert((NEON_LD2_s | (1 << NEONLSSize_offset)) == NEON_LD2_d,
                    "LSB of size distinguishes S and D registers.");
      mnemonic = (instr->NEONLoad() == 1) ? "ld2" : "st2";
      if ((instr->NEONLSSize() & 1) == 0) {
        form = "{'Vt.s, 'Vt2.s}['IVLSLane2], ['Xns]";
      } else {
        form = "{'Vt.d, 'Vt2.d}['IVLSLane3], ['Xns]";
      }
      break;
    case NEON_LD2R:
      mnemonic = "ld2r";
      form = "{'Vt.%s, 'Vt2.%s}, ['Xns]";
      break;
    case NEON_LD3_b:
    case NEON_ST3_b:
      mnemonic = (instr->NEONLoad() == 1) ? "ld3" : "st3";
      form = "{'Vt.b, 'Vt2.b, 'Vt3.b}['IVLSLane0], ['Xns]";
      break;
    case NEON_LD3_h:
    case NEON_ST3_h:
      mnemonic = (instr->NEONLoad() == 1) ? "ld3" : "st3";
      form = "{'Vt.h, 'Vt2.h, 'Vt3.h}['IVLSLane1], ['Xns]";
      break;
    case NEON_LD3_s:
    case NEON_ST3_s:
      mnemonic = (instr->NEONLoad() == 1) ? "ld3" : "st3";
      if ((instr->NEONLSSize() & 1) == 0) {
        form = "{'Vt.s, 'Vt2.s, 'Vt3.s}['IVLSLane2], ['Xns]";
      } else {
        form = "{'Vt.d, 'Vt2.d, 'Vt3.d}['IVLSLane3], ['Xns]";
      }
      break;
    case NEON_LD3R:
      mnemonic = "ld3r";
      form = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s}, ['Xns]";
      break;
    case NEON_LD4_b:
    case NEON_ST4_b:
      mnemonic = (instr->NEONLoad() == 1) ? "ld4" : "st4";
      form = "{'Vt.b, 'Vt2.b, 'Vt3.b, 'Vt4.b}['IVLSLane0], ['Xns]";
      break;
    case NEON_LD4_h:
    case NEON_ST4_h:
      mnemonic = (instr->NEONLoad() == 1) ? "ld4" : "st4";
      form = "{'Vt.h, 'Vt2.h, 'Vt3.h, 'Vt4.h}['IVLSLane1], ['Xns]";
      break;
    case NEON_LD4_s:
    case NEON_ST4_s:
      static_assert((NEON_LD4_s | (1 << NEONLSSize_offset)) == NEON_LD4_d,
                    "LSB of size distinguishes S and D registers.");
      static_assert((NEON_ST4_s | (1 << NEONLSSize_offset)) == NEON_ST4_d,
                    "LSB of size distinguishes S and D registers.");
      mnemonic = (instr->NEONLoad() == 1) ? "ld4" : "st4";
      if ((instr->NEONLSSize() & 1) == 0) {
        form = "{'Vt.s, 'Vt2.s, 'Vt3.s, 'Vt4.s}['IVLSLane2], ['Xns]";
      } else {
        form = "{'Vt.d, 'Vt2.d, 'Vt3.d, 'Vt4.d}['IVLSLane3], ['Xns]";
      }
      break;
    case NEON_LD4R:
      mnemonic = "ld4r";
      form = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s, 'Vt4.%s}, ['Xns]";
      break;
    default:
      break;
  }

  // Work out unallocated encodings.
  bool allocated = (mnemonic != nullptr);
  switch (instr->Mask(NEONLoadStoreSingleStructMask)) {
    case NEON_LD1_h:
    case NEON_LD2_h:
    case NEON_LD3_h:
    case NEON_LD4_h:
    case NEON_ST1_h:
    case NEON_ST2_h:
    case NEON_ST3_h:
    case NEON_ST4_h:
      DCHECK(allocated);
      allocated = ((instr->NEONLSSize() & 1) == 0);
      break;
    case NEON_LD1_s:
    case NEON_LD2_s:
    case NEON_LD3_s:
    case NEON_LD4_s:
    case NEON_ST1_s:
    case NEON_ST2_s:
    case NEON_ST3_s:
    case NEON_ST4_s:
      DCHECK(allocated);
      allocated = (instr->NEONLSSize() <= 1) &&
                  ((instr->NEONLSSize() == 0) || (instr->NEONS() == 0));
      break;
    case NEON_LD1R:
    case NEON_LD2R:
    case NEON_LD3R:
    case NEON_LD4R:
      DCHECK(allocated);
      allocated = (instr->NEONS() == 0);
      break;
    default:
      break;
  }
  if (allocated) {
    DCHECK_NOT_NULL(mnemonic);
    DCHECK_NOT_NULL(form);
  } else {
    mnemonic = "unallocated";
    form = "(NEONLoadStoreSingleStruct)";
  }

  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONLoadStoreSingleStructPostIndex(
    Instruction* instr) {
  const char* mnemonic = nullptr;
  const char* form = nullptr;

  const char* form_1b = "{'Vt.b}['IVLSLane0], ['Xns], 'Xmb1";
  const char* form_1h = "{'Vt.h}['IVLSLane1], ['Xns], 'Xmb2";
  const char* form_1s = "{'Vt.s}['IVLSLane2], ['Xns], 'Xmb4";
  const char* form_1d = "{'Vt.d}['IVLSLane3], ['Xns], 'Xmb8";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LoadStoreFormatMap());

  switch (instr->Mask(NEONLoadStoreSingleStructPostIndexMask)) {
    case NEON_LD1_b_post:
      mnemonic = "ld1";
      form = form_1b;
      break;
    case NEON_LD1_h_post:
      mnemonic = "ld1";
      form = form_1h;
      break;
    case NEON_LD1_s_post:
      mnemonic = "ld1";
      static_assert((NEON_LD1_s | (1 << NEONLSSize_offset)) == NEON_LD1_d,
                    "LSB of size distinguishes S and D registers.");
      form = ((instr->NEONLSSize() & 1) == 0) ? form_1s : form_1d;
      break;
    case NEON_ST1_b_post:
      mnemonic = "st1";
      form = form_1b;
      break;
    case NEON_ST1_h_post:
      mnemonic = "st1";
      form = form_1h;
      break;
    case NEON_ST1_s_post:
      mnemonic = "st1";
      static_assert((NEON_ST1_s | (1 << NEONLSSize_offset)) == NEON_ST1_d,
                    "LSB of size distinguishes S and D registers.");
      form = ((instr->NEONLSSize() & 1) == 0) ? form_1s : form_1d;
      break;
    case NEON_LD1R_post:
      mnemonic = "ld1r";
      form = "{'Vt.%s}, ['Xns], 'Xmz1";
      break;
    case NEON_LD2_b_post:
    case NEON_ST2_b_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld2" : "st2";
      form = "{'Vt.b, 'Vt2.b}['IVLSLane0], ['Xns], 'Xmb2";
      break;
    case NEON_ST2_h_post:
    case NEON_LD2_h_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld2" : "st2";
      form = "{'Vt.h, 'Vt2.h}['IVLSLane1], ['Xns], 'Xmb4";
      break;
    case NEON_LD2_s_post:
    case NEON_ST2_s_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld2" : "st2";
      if ((instr->NEONLSSize() & 1) == 0)
        form = "{'Vt.s, 'Vt2.s}['IVLSLane2], ['Xns], 'Xmb8";
      else
        form = "{'Vt.d, 'Vt2.d}['IVLSLane3], ['Xns], 'Xmb16";
      break;
    case NEON_LD2R_post:
      mnemonic = "ld2r";
      form = "{'Vt.%s, 'Vt2.%s}, ['Xns], 'Xmz2";
      break;
    case NEON_LD3_b_post:
    case NEON_ST3_b_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld3" : "st3";
      form = "{'Vt.b, 'Vt2.b, 'Vt3.b}['IVLSLane0], ['Xns], 'Xmb3";
      break;
    case NEON_LD3_h_post:
    case NEON_ST3_h_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld3" : "st3";
      form = "{'Vt.h, 'Vt2.h, 'Vt3.h}['IVLSLane1], ['Xns], 'Xmb6";
      break;
    case NEON_LD3_s_post:
    case NEON_ST3_s_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld3" : "st3";
      if ((instr->NEONLSSize() & 1) == 0)
        form = "{'Vt.s, 'Vt2.s, 'Vt3.s}['IVLSLane2], ['Xns], 'Xmb12";
      else
        form = "{'Vt.d, 'Vt2.d, 'Vt3.d}['IVLSLane3], ['Xns], 'Xmb24";
      break;
    case NEON_LD3R_post:
      mnemonic = "ld3r";
      form = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s}, ['Xns], 'Xmz3";
      break;
    case NEON_LD4_b_post:
    case NEON_ST4_b_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld4" : "st4";
      form = "{'Vt.b, 'Vt2.b, 'Vt3.b, 'Vt4.b}['IVLSLane0], ['Xns], 'Xmb4";
      break;
    case NEON_LD4_h_post:
    case NEON_ST4_h_post:
      mnemonic = (instr->NEONLoad()) == 1 ? "ld4" : "st4";
      form = "{'Vt.h, 'Vt2.h, 'Vt3.h, 'Vt4.h}['IVLSLane1], ['Xns], 'Xmb8";
      break;
    case NEON_LD4_s_post:
    case NEON_ST4_s_post:
      mnemonic = (instr->NEONLoad() == 1) ? "ld4" : "st4";
      if ((instr->NEONLSSize() & 1) == 0)
        form = "{'Vt.s, 'Vt2.s, 'Vt3.s, 'Vt4.s}['IVLSLane2], ['Xns], 'Xmb16";
      else
        form = "{'Vt.d, 'Vt2.d, 'Vt3.d, 'Vt4.d}['IVLSLane3], ['Xns], 'Xmb32";
      break;
    case NEON_LD4R_post:
      mnemonic = "ld4r";
      form = "{'Vt.%s, 'Vt2.%s, 'Vt3.%s, 'Vt4.%s}, ['Xns], 'Xmz4";
      break;
    default:
      break;
  }

  // Work out unallocated encodings.
  bool allocated = (mnemonic != nullptr);
  switch (instr->Mask(NEONLoadStoreSingleStructPostIndexMask)) {
    case NEON_LD1_h_post:
    case NEON_LD2_h_post:
    case NEON_LD3_h_post:
    case NEON_LD4_h_post:
    case NEON_ST1_h_post:
    case NEON_ST2_h_post:
    case NEON_ST3_h_post:
    case NEON_ST4_h_post:
      DCHECK(allocated);
      allocated = ((instr->NEONLSSize() & 1) == 0);
      break;
    case NEON_LD1_s_post:
    case NEON_LD2_s_post:
    case NEON_LD3_s_post:
    case NEON_LD4_s_post:
    case NEON_ST1_s_post:
    case NEON_ST2_s_post:
    case NEON_ST3_s_post:
    case NEON_ST4_s_post:
      DCHECK(allocated);
      allocated = (instr->NEONLSSize() <= 1) &&
                  ((instr->NEONLSSize() == 0) || (instr->NEONS() == 0));
      break;
    case NEON_LD1R_post:
    case NEON_LD2R_post:
    case NEON_LD3R_post:
    case NEON_LD4R_post:
      DCHECK(allocated);
      allocated = (instr->NEONS() == 0);
      break;
    default:
      break;
  }
  if (allocated) {
    DCHECK_NOT_NULL(mnemonic);
    DCHECK_NOT_NULL(form);
  } else {
    mnemonic = "unallocated";
    form = "(NEONLoadStoreSingleStructPostIndex)";
  }

  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONModifiedImmediate(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vt.%s, 'IVMIImm8, lsl 'IVMIShiftAmt1";

  int cmode = instr->NEONCmode();
  int cmode_3 = (cmode >> 3) & 1;
  int cmode_2 = (cmode >> 2) & 1;
  int cmode_1 = (cmode >> 1) & 1;
  int cmode_0 = cmode & 1;
  int q = instr->NEONQ();
  int op = instr->NEONModImmOp();

  static const NEONFormatMap map_b = {{30}, {NF_8B, NF_16B}};
  static const NEONFormatMap map_h = {{30}, {NF_4H, NF_8H}};
  static const NEONFormatMap map_s = {{30}, {NF_2S, NF_4S}};
  NEONFormatDecoder nfd(instr, &map_b);

  if (cmode_3 == 0) {
    if (cmode_0 == 0) {
      mnemonic = (op == 1) ? "mvni" : "movi";
    } else {  // cmode<0> == '1'.
      mnemonic = (op == 1) ? "bic" : "orr";
    }
    nfd.SetFormatMap(0, &map_s);
  } else {  // cmode<3> == '1'.
    if (cmode_2 == 0) {
      if (cmode_0 == 0) {
        mnemonic = (op == 1) ? "mvni" : "movi";
      } else {  // cmode<0> == '1'.
        mnemonic = (op == 1) ? "bic" : "orr";
      }
      nfd.SetFormatMap(0, &map_h);
    } else {  // cmode<2> == '1'.
      if (cmode_1 == 0) {
        mnemonic = (op == 1) ? "mvni" : "movi";
        form = "'Vt.%s, 'IVMIImm8, msl 'IVMIShiftAmt2";
        nfd.SetFormatMap(0, &map_s);
      } else {  // cmode<1> == '1'.
        if (cmode_0 == 0) {
          mnemonic = "movi";
          if (op == 0) {
            form = "'Vt.%s, 'IVMIImm8";
          } else {
            form = (q == 0) ? "'Dd, 'IVMIImm" : "'Vt.2d, 'IVMIImm";
          }
        } else {  // cmode<0> == '1'
          mnemonic = "fmov";
          if (op == 0) {
            form = "'Vt.%s, 'IVMIImmFPSingle";
            nfd.SetFormatMap(0, &map_s);
          } else {
            if (q == 1) {
              form = "'Vt.2d, 'IVMIImmFPDouble";
            } else {
              mnemonic = "unallocated";
              form = "(NEONModifiedImmediate)";
            }
          }
        }
      }
    }
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONPerm(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vd.%s, 'Vn.%s, 'Vm.%s";
  NEONFormatDecoder nfd(instr);

  switch (instr->Mask(NEONPermMask)) {
    case NEON_TRN1:
      mnemonic = "trn1";
      break;
    case NEON_TRN2:
      mnemonic = "trn2";
      break;
    case NEON_UZP1:
      mnemonic = "uzp1";
      break;
    case NEON_UZP2:
      mnemonic = "uzp2";
      break;
    case NEON_ZIP1:
      mnemonic = "zip1";
      break;
    case NEON_ZIP2:
      mnemonic = "zip2";
      break;
    default:
      form = "(NEONPerm)";
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONScalar2RegMisc(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, %sn";
  const char* form_0 = "%sd, %sn, #0";
  const char* form_fp0 = "%sd, %sn, #0.0";

  NEONFormatDecoder nfd(instr, NEONFormatDecoder::ScalarFormatMap());

  if (instr->Mask(NEON2RegMiscOpcode) <= NEON_NEG_scalar_opcode) {
    // These instructions all use a two bit size field, except NOT and RBIT,
    // which use the field to encode the operation.
    switch (instr->Mask(NEONScalar2RegMiscMask)) {
      case NEON_CMGT_zero_scalar:
        mnemonic = "cmgt";
        form = form_0;
        break;
      case NEON_CMGE_zero_scalar:
        mnemonic = "cmge";
        form = form_0;
        break;
      case NEON_CMLE_zero_scalar:
        mnemonic = "cmle";
        form = form_0;
        break;
      case NEON_CMLT_zero_scalar:
        mnemonic = "cmlt";
        form = form_0;
        break;
      case NEON_CMEQ_zero_scalar:
        mnemonic = "cmeq";
        form = form_0;
        break;
      case NEON_NEG_scalar:
        mnemonic = "neg";
        break;
      case NEON_SQNEG_scalar:
        mnemonic = "sqneg";
        break;
      case NEON_ABS_scalar:
        mnemonic = "abs";
        break;
      case NEON_SQABS_scalar:
        mnemonic = "sqabs";
        break;
      case NEON_SUQADD_scalar:
        mnemonic = "suqadd";
        break;
      case NEON_USQADD_scalar:
        mnemonic = "usqadd";
        break;
      default:
        form = "(NEONScalar2RegMisc)";
    }
  } else {
    // These instructions all use a one bit size field, except SQXTUN, SQXTN
    // and UQXTN, which use a two bit size field.
    nfd.SetFormatMaps(nfd.FPScalarFormatMap());
    switch (instr->Mask(NEONScalar2RegMiscFPMask)) {
      case NEON_FRSQRTE_scalar:
        mnemonic = "frsqrte";
        break;
      case NEON_FRECPE_scalar:
        mnemonic = "frecpe";
        break;
      case NEON_SCVTF_scalar:
        mnemonic = "scvtf";
        break;
      case NEON_UCVTF_scalar:
        mnemonic = "ucvtf";
        break;
      case NEON_FCMGT_zero_scalar:
        mnemonic = "fcmgt";
        form = form_fp0;
        break;
      case NEON_FCMGE_zero_scalar:
        mnemonic = "fcmge";
        form = form_fp0;
        break;
      case NEON_FCMLE_zero_scalar:
        mnemonic = "fcmle";
        form = form_fp0;
        break;
      case NEON_FCMLT_zero_scalar:
        mnemonic = "fcmlt";
        form = form_fp0;
        break;
      case NEON_FCMEQ_zero_scalar:
        mnemonic = "fcmeq";
        form = form_fp0;
        break;
      case NEON_FRECPX_scalar:
        mnemonic = "frecpx";
        break;
      case NEON_FCVTNS_scalar:
        mnemonic = "fcvtns";
        break;
      case NEON_FCVTNU_scalar:
        mnemonic = "fcvtnu";
        break;
      case NEON_FCVTPS_scalar:
        mnemonic = "fcvtps";
        break;
      case NEON_FCVTPU_scalar:
        mnemonic = "fcvtpu";
        break;
      case NEON_FCVTMS_scalar:
        mnemonic = "fcvtms";
        break;
      case NEON_FCVTMU_scalar:
        mnemonic = "fcvtmu";
        break;
      case NEON_FCVTZS_scalar:
        mnemonic = "fcvtzs";
        break;
      case NEON_FCVTZU_scalar:
        mnemonic = "fcvtzu";
        break;
      case NEON_FCVTAS_scalar:
        mnemonic = "fcvtas";
        break;
      case NEON_FCVTAU_scalar:
        mnemonic = "fcvtau";
        break;
      case NEON_FCVTXN_scalar:
        nfd.SetFormatMap(0, nfd.LongScalarFormatMap());
        mnemonic = "fcvtxn";
        break;
      default:
        nfd.SetFormatMap(0, nfd.ScalarFormatMap());
        nfd.SetFormatMap(1, nfd.LongScalarFormatMap());
        switch (instr->Mask(NEONScalar2RegMiscMask)) {
          case NEON_SQXTN_scalar:
            mnemonic = "sqxtn";
            break;
          case NEON_UQXTN_scalar:
            mnemonic = "uqxtn";
            break;
          case NEON_SQXTUN_scalar:
            mnemonic = "sqxtun";
            break;
          default:
            form = "(NEONScalar2RegMisc)";
        }
    }
  }
  Format(instr, mnemonic, nfd.SubstitutePlaceholders(form));
}

void DisassemblingDecoder::VisitNEONScalar3Diff(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, %sn, %sm";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::LongScalarFormatMap(),
                        NEONFormatDecoder::ScalarFormatMap());

  switch (instr->Mask(NEONScalar3DiffMask)) {
    case NEON_SQDMLAL_scalar:
      mnemonic = "sqdmlal";
      break;
    case NEON_SQDMLSL_scalar:
      mnemonic = "sqdmlsl";
      break;
    case NEON_SQDMULL_scalar:
      mnemonic = "sqdmull";
      break;
    default:
      form = "(NEONScalar3Diff)";
  }
  Format(instr, mnemonic, nfd.SubstitutePlaceholders(form));
}

void DisassemblingDecoder::VisitNEONScalar3Same(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, %sn, %sm";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::ScalarFormatMap());

  if (instr->Mask(NEONScalar3SameFPFMask) == NEONScalar3SameFPFixed) {
    nfd.SetFormatMaps(nfd.FPScalarFormatMap());
    switch (instr->Mask(NEONScalar3SameFPMask)) {
      case NEON_FACGE_scalar:
        mnemonic = "facge";
        break;
      case NEON_FACGT_scalar:
        mnemonic = "facgt";
        break;
      case NEON_FCMEQ_scalar:
        mnemonic = "fcmeq";
        break;
      case NEON_FCMGE_scalar:
        mnemonic = "fcmge";
        break;
      case NEON_FCMGT_scalar:
        mnemonic = "fcmgt";
        break;
      case NEON_FMULX_scalar:
        mnemonic = "fmulx";
        break;
      case NEON_FRECPS_scalar:
        mnemonic = "frecps";
        break;
      case NEON_FRSQRTS_scalar:
        mnemonic = "frsqrts";
        break;
      case NEON_FABD_scalar:
        mnemonic = "fabd";
        break;
      default:
        form = "(NEONScalar3Same)";
    }
  } else {
    switch (instr->Mask(NEONScalar3SameMask)) {
      case NEON_ADD_scalar:
        mnemonic = "add";
        break;
      case NEON_SUB_scalar:
        mnemonic = "sub";
        break;
      case NEON_CMEQ_scalar:
        mnemonic = "cmeq";
        break;
      case NEON_CMGE_scalar:
        mnemonic = "cmge";
        break;
      case NEON_CMGT_scalar:
        mnemonic = "cmgt";
        break;
      case NEON_CMHI_scalar:
        mnemonic = "cmhi";
        break;
      case NEON_CMHS_scalar:
        mnemonic = "cmhs";
        break;
      case NEON_CMTST_scalar:
        mnemonic = "cmtst";
        break;
      case NEON_UQADD_scalar:
        mnemonic = "uqadd";
        break;
      case NEON_SQADD_scalar:
        mnemonic = "sqadd";
        break;
      case NEON_UQSUB_scalar:
        mnemonic = "uqsub";
        break;
      case NEON_SQSUB_scalar:
        mnemonic = "sqsub";
        break;
      case NEON_USHL_scalar:
        mnemonic = "ushl";
        break;
      case NEON_SSHL_scalar:
        mnemonic = "sshl";
        break;
      case NEON_UQSHL_scalar:
        mnemonic = "uqshl";
        break;
      case NEON_SQSHL_scalar:
        mnemonic = "sqshl";
        break;
      case NEON_URSHL_scalar:
        mnemonic = "urshl";
        break;
      case NEON_SRSHL_scalar:
        mnemonic = "srshl";
        break;
      case NEON_UQRSHL_scalar:
        mnemonic = "uqrshl";
        break;
      case NEON_SQRSHL_scalar:
        mnemonic = "sqrshl";
        break;
      case NEON_SQDMULH_scalar:
        mnemonic = "sqdmulh";
        break;
      case NEON_SQRDMULH_scalar:
        mnemonic = "sqrdmulh";
        break;
      default:
        form = "(NEONScalar3Same)";
    }
  }
  Format(instr, mnemonic, nfd.SubstitutePlaceholders(form));
}

void DisassemblingDecoder::VisitNEONScalarByIndexedElement(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, %sn, 'Ve.%s['IVByElemIndex]";
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::ScalarFormatMap());
  bool long_instr = false;

  switch (instr->Mask(NEONScalarByIndexedElementMask)) {
    case NEON_SQDMULL_byelement_scalar:
      mnemonic = "sqdmull";
      long_instr = true;
      break;
    case NEON_SQDMLAL_byelement_scalar:
      mnemonic = "sqdmlal";
      long_instr = true;
      break;
    case NEON_SQDMLSL_byelement_scalar:
      mnemonic = "sqdmlsl";
      long_instr = true;
      break;
    case NEON_SQDMULH_byelement_scalar:
      mnemonic = "sqdmulh";
      break;
    case NEON_SQRDMULH_byelement_scalar:
      mnemonic = "sqrdmulh";
      break;
    default:
      nfd.SetFormatMap(0, nfd.FPScalarFormatMap());
      switch (instr->Mask(NEONScalarByIndexedElementFPMask)) {
        case NEON_FMUL_byelement_scalar:
          mnemonic = "fmul";
          break;
        case NEON_FMLA_byelement_scalar:
          mnemonic = "fmla";
          break;
        case NEON_FMLS_byelement_scalar:
          mnemonic = "fmls";
          break;
        case NEON_FMULX_byelement_scalar:
          mnemonic = "fmulx";
          break;
        default:
          form = "(NEONScalarByIndexedElement)";
      }
  }

  if (long_instr) {
    nfd.SetFormatMap(0, nfd.LongScalarFormatMap());
  }

  Format(instr, mnemonic,
         nfd.Substitute(form, nfd.kPlaceholder, nfd.kPlaceholder, nfd.kFormat));
}

void DisassemblingDecoder::VisitNEONScalarCopy(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(NEONScalarCopy)";

  NEONFormatDecoder nfd(instr, NEONFormatDecoder::TriangularScalarFormatMap());

  if (instr->Mask(NEONScalarCopyMask) == NEON_DUP_ELEMENT_scalar) {
    mnemonic = "mov";
    form = "%sd, 'Vn.%s['IVInsIndex1]";
  }

  Format(instr, mnemonic, nfd.Substitute(form, nfd.kPlaceholder, nfd.kFormat));
}

void DisassemblingDecoder::VisitNEONScalarPairwise(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, 'Vn.%s";
  NEONFormatMap map = {{22}, {NF_2S, NF_2D}};
  NEONFormatDecoder nfd(instr, NEONFormatDecoder::FPScalarFormatMap(), &map);

  switch (instr->Mask(NEONScalarPairwiseMask)) {
    case NEON_ADDP_scalar:
      mnemonic = "addp";
      break;
    case NEON_FADDP_scalar:
      mnemonic = "faddp";
      break;
    case NEON_FMAXP_scalar:
      mnemonic = "fmaxp";
      break;
    case NEON_FMAXNMP_scalar:
      mnemonic = "fmaxnmp";
      break;
    case NEON_FMINP_scalar:
      mnemonic = "fminp";
      break;
    case NEON_FMINNMP_scalar:
      mnemonic = "fminnmp";
      break;
    default:
      form = "(NEONScalarPairwise)";
  }
  Format(instr, mnemonic,
         nfd.Substitute(form, NEONFormatDecoder::kPlaceholder,
                        NEONFormatDecoder::kFormat));
}

void DisassemblingDecoder::VisitNEONScalarShiftImmediate(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "%sd, %sn, 'Is1";
  const char* form_2 = "%sd, %sn, 'Is2";

  static const NEONFormatMap map_shift = {
      {22, 21, 20, 19},
      {NF_UNDEF, NF_B, NF_H, NF_H, NF_S, NF_S, NF_S, NF_S, NF_D, NF_D, NF_D,
       NF_D, NF_D, NF_D, NF_D, NF_D}};
  static const NEONFormatMap map_shift_narrow = {
      {21, 20, 19}, {NF_UNDEF, NF_H, NF_S, NF_S, NF_D, NF_D, NF_D, NF_D}};
  NEONFormatDecoder nfd(instr, &map_shift);

  if (instr->ImmNEONImmh()) {  // immh has to be non-zero.
    switch (instr->Mask(NEONScalarShiftImmediateMask)) {
      case NEON_FCVTZU_imm_scalar:
        mnemonic = "fcvtzu";
        break;
      case NEON_FCVTZS_imm_scalar:
        mnemonic = "fcvtzs";
        break;
      case NEON_SCVTF_imm_scalar:
        mnemonic = "scvtf";
        break;
      case NEON_UCVTF_imm_scalar:
        mnemonic = "ucvtf";
        break;
      case NEON_SRI_scalar:
        mnemonic = "sri";
        break;
      case NEON_SSHR_scalar:
        mnemonic = "sshr";
        break;
      case NEON_USHR_scalar:
        mnemonic = "ushr";
        break;
      case NEON_SRSHR_scalar:
        mnemonic = "srshr";
        break;
      case NEON_URSHR_scalar:
        mnemonic = "urshr";
        break;
      case NEON_SSRA_scalar:
        mnemonic = "ssra";
        break;
      case NEON_USRA_scalar:
        mnemonic = "usra";
        break;
      case NEON_SRSRA_scalar:
        mnemonic = "srsra";
        break;
      case NEON_URSRA_scalar:
        mnemonic = "ursra";
        break;
      case NEON_SHL_scalar:
        mnemonic = "shl";
        form = form_2;
        break;
      case NEON_SLI_scalar:
        mnemonic = "sli";
        form = form_2;
        break;
      case NEON_SQSHLU_scalar:
        mnemonic = "sqshlu";
        form = form_2;
        break;
      case NEON_SQSHL_imm_scalar:
        mnemonic = "sqshl";
        form = form_2;
        break;
      case NEON_UQSHL_imm_scalar:
        mnemonic = "uqshl";
        form = form_2;
        break;
      case NEON_UQSHRN_scalar:
        mnemonic = "uqshrn";
        nfd.SetFormatMap(1, &map_shift_narrow);
        break;
      case NEON_UQRSHRN_scalar:
        mnemonic = "uqrshrn";
        nfd.SetFormatMap(1, &map_shift_narrow);
        break;
      case NEON_SQSHRN_scalar:
        mnemonic = "sqshrn";
        nfd.SetFormatMap(1, &map_shift_narrow);
        break;
      case NEON_SQRSHRN_scalar:
        mnemonic = "sqrshrn";
        nfd.SetFormatMap(1, &map_shift_narrow);
        break;
      case NEON_SQSHRUN_scalar:
        mnemonic = "sqshrun";
        nfd.SetFormatMap(1, &map_shift_narrow);
        break;
      case NEON_SQRSHRUN_scalar:
        mnemonic = "sqrshrun";
        nfd.SetFormatMap(1, &map_shift_narrow);
        break;
      default:
        form = "(NEONScalarShiftImmediate)";
    }
  } else {
    form = "(NEONScalarShiftImmediate)";
  }
  Format(instr, mnemonic, nfd.SubstitutePlaceholders(form));
}

void DisassemblingDecoder::VisitNEONShiftImmediate(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "'Vd.%s, 'Vn.%s, 'Is1";
  const char* form_shift_2 = "'Vd.%s, 'Vn.%s, 'Is2";
  const char* form_xtl = "'Vd.%s, 'Vn.%s";

  // 0001->8H, 001x->4S, 01xx->2D, all others undefined.
  static const NEONFormatMap map_shift_ta = {
      {22, 21, 20, 19},
      {NF_UNDEF, NF_8H, NF_4S, NF_4S, NF_2D, NF_2D, NF_2D, NF_2D}};

  // 00010->8B, 00011->16B, 001x0->4H, 001x1->8H,
  // 01xx0->2S, 01xx1->4S, 1xxx1->2D, all others undefined.
  static const NEONFormatMap map_shift_tb = {
      {22, 21, 20, 19, 30},
      {NF_UNDEF, NF_UNDEF, NF_8B,    NF_16B, NF_4H,    NF_8H, NF_4H,    NF_8H,
       NF_2S,    NF_4S,    NF_2S,    NF_4S,  NF_2S,    NF_4S, NF_2S,    NF_4S,
       NF_UNDEF, NF_2D,    NF_UNDEF, NF_2D,  NF_UNDEF, NF_2D, NF_UNDEF, NF_2D,
       NF_UNDEF, NF_2D,    NF_UNDEF, NF_2D,  NF_UNDEF, NF_2D, NF_UNDEF, NF_2D}};

  NEONFormatDecoder nfd(instr, &map_shift_tb);

  if (instr->ImmNEONImmh()) {  // immh has to be non-zero.
    switch (instr->Mask(NEONShiftImmediateMask)) {
      case NEON_SQSHLU:
        mnemonic = "sqshlu";
        form = form_shift_2;
        break;
      case NEON_SQSHL_imm:
        mnemonic = "sqshl";
        form = form_shift_2;
        break;
      case NEON_UQSHL_imm:
        mnemonic = "uqshl";
        form = form_shift_2;
        break;
      case NEON_SHL:
        mnemonic = "shl";
        form = form_shift_2;
        break;
      case NEON_SLI:
        mnemonic = "sli";
        form = form_shift_2;
        break;
      case NEON_SCVTF_imm:
        mnemonic = "scvtf";
        break;
      case NEON_UCVTF_imm:
        mnemonic = "ucvtf";
        break;
      case NEON_FCVTZU_imm:
        mnemonic = "fcvtzu";
        break;
      case NEON_FCVTZS_imm:
        mnemonic = "fcvtzs";
        break;
      case NEON_SRI:
        mnemonic = "sri";
        break;
      case NEON_SSHR:
        mnemonic = "sshr";
        break;
      case NEON_USHR:
        mnemonic = "ushr";
        break;
      case NEON_SRSHR:
        mnemonic = "srshr";
        break;
      case NEON_URSHR:
        mnemonic = "urshr";
        break;
      case NEON_SSRA:
        mnemonic = "ssra";
        break;
      case NEON_USRA:
        mnemonic = "usra";
        break;
      case NEON_SRSRA:
        mnemonic = "srsra";
        break;
      case NEON_URSRA:
        mnemonic = "ursra";
        break;
      case NEON_SHRN:
        mnemonic = instr->Mask(NEON_Q) ? "shrn2" : "shrn";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_RSHRN:
        mnemonic = instr->Mask(NEON_Q) ? "rshrn2" : "rshrn";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_UQSHRN:
        mnemonic = instr->Mask(NEON_Q) ? "uqshrn2" : "uqshrn";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_UQRSHRN:
        mnemonic = instr->Mask(NEON_Q) ? "uqrshrn2" : "uqrshrn";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_SQSHRN:
        mnemonic = instr->Mask(NEON_Q) ? "sqshrn2" : "sqshrn";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_SQRSHRN:
        mnemonic = instr->Mask(NEON_Q) ? "sqrshrn2" : "sqrshrn";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_SQSHRUN:
        mnemonic = instr->Mask(NEON_Q) ? "sqshrun2" : "sqshrun";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_SQRSHRUN:
        mnemonic = instr->Mask(NEON_Q) ? "sqrshrun2" : "sqrshrun";
        nfd.SetFormatMap(1, &map_shift_ta);
        break;
      case NEON_SSHLL:
        nfd.SetFormatMap(0, &map_shift_ta);
        if (instr->ImmNEONImmb() == 0 &&
            CountSetBits(instr->ImmNEONImmh(), 32) == 1) {  // sxtl variant.
          form = form_xtl;
          mnemonic = instr->Mask(NEON_Q) ? "sxtl2" : "sxtl";
        } else {  // sshll variant.
          form = form_shift_2;
          mnemonic = instr->Mask(NEON_Q) ? "sshll2" : "sshll";
        }
        break;
      case NEON_USHLL:
        nfd.SetFormatMap(0, &map_shift_ta);
        if (instr->ImmNEONImmb() == 0 &&
            CountSetBits(instr->ImmNEONImmh(), 32) == 1) {  // uxtl variant.
          form = form_xtl;
          mnemonic = instr->Mask(NEON_Q) ? "uxtl2" : "uxtl";
        } else {  // ushll variant.
          form = form_shift_2;
          mnemonic = instr->Mask(NEON_Q) ? "ushll2" : "ushll";
        }
        break;
      default:
        form = "(NEONShiftImmediate)";
    }
  } else {
    form = "(NEONShiftImmediate)";
  }
  Format(instr, mnemonic, nfd.Substitute(form));
}

void DisassemblingDecoder::VisitNEONTable(Instruction* instr) {
  const char* mnemonic = "unimplemented";
  const char* form = "(NEONTable)";
  const char form_1v[] = "'Vd.%%s, {'Vn.16b}, 'Vm.%%s";
  const char form_2v[] = "'Vd.%%s, {'Vn.16b, v%d.16b}, 'Vm.%%s";
  const char form_3v[] = "'Vd.%%s, {'Vn.16b, v%d.16b, v%d.16b}, 'Vm.%%s";
  const char form_4v[] =
      "'Vd.%%s, {'Vn.16b, v%d.16b, v%d.16b, v%d.16b}, 'Vm.%%s";
  static const NEONFormatMap map_b = {{30}, {NF_8B, NF_16B}};
  NEONFormatDecoder nfd(instr, &map_b);

  switch (instr->Mask(NEONTableMask)) {
    case NEON_TBL_1v:
      mnemonic = "tbl";
      form = form_1v;
      break;
    case NEON_TBL_2v:
      mnemonic = "tbl";
      form = form_2v;
      break;
    case NEON_TBL_3v:
      mnemonic = "tbl";
      form = form_3v;
      break;
    case NEON_TBL_4v:
      mnemonic = "tbl";
      form = form_4v;
      break;
    case NEON_TBX_1v:
      mnemonic = "tbx";
      form = form_1v;
      break;
    case NEON_TBX_2v:
      mnemonic = "tbx";
      form = form_2v;
      break;
    case NEON_TBX_3v:
      mnemonic = "tbx";
      form = form_3v;
      break;
    case NEON_TBX_4v:
      mnemonic = "tbx";
      form = form_4v;
      break;
    default:
      break;
  }

  char re_form[sizeof(form_4v)];
  int reg_num = instr->Rn();
  snprintf(re_form, sizeof(re_form), form, (reg_num + 1) % kNumberOfVRegisters,
           (reg_num + 2) % kNumberOfVRegisters,
           (reg_num + 3) % kNumberOfVRegisters);

  Format(instr, mnemonic, nfd.Substitute(re_form));
}

void DisassemblingDecoder::VisitUnimplemented(Instruction* instr) {
  Format(instr, "unimplemented", "(Unimplemented)");
}

void DisassemblingDecoder::VisitUnallocated(Instruction* instr) {
  Format(instr, "unallocated", "(Unallocated)");
}

void DisassemblingDecoder::ProcessOutput(Instruction* /*instr*/) {
  // The base disasm does nothing more than disassembling into a buffer.
}

void DisassemblingDecoder::AppendRegisterNameToOutput(const CPURegister& reg) {
  DCHECK(reg.is_valid());
  char reg_char;

  if (reg.IsRegister()) {
    reg_char = reg.Is64Bits() ? 'x' : 'w';
  } else {
    DCHECK(reg.IsVRegister());
    switch (reg.SizeInBits()) {
      case kBRegSizeInBits:
        reg_char = 'b';
        break;
      case kHRegSizeInBits:
        reg_char = 'h';
        break;
      case kSRegSizeInBits:
        reg_char = 's';
        break;
      case kDRegSizeInBits:
        reg_char = 'd';
        break;
      default:
        DCHECK(reg.Is128Bits());
        reg_char = 'q';
    }
  }

  if (reg.IsVRegister() || !(reg.Aliases(sp) || reg.Aliases(xzr))) {
    // Filter special registers
    if (reg.IsX() && (reg.code() == 27)) {
      AppendToOutput("cp");
    } else if (reg.IsX() && (reg.code() == 29)) {
      AppendToOutput("fp");
    } else if (reg.IsX() && (reg.code() == 30)) {
      AppendToOutput("lr");
    } else {
      // A core or scalar/vector register: [wx]0 - 30, [bhsdq]0 - 31.
      AppendToOutput("%c%d", reg_char, reg.code());
    }
  } else if (reg.Aliases(sp)) {
    // Disassemble w31/x31 as stack pointer wsp/sp.
    AppendToOutput("%s", reg.Is64Bits() ? "sp" : "wsp");
  } else {
    // Disassemble w31/x31 as zero register wzr/xzr.
    AppendToOutput("%czr", reg_char);
  }
}

void DisassemblingDecoder::Format(Instruction* instr, const char* mnemonic,
                                  const char* format) {
  // TODO(mcapewel) don't think I can use the instr address here - there needs
  //                to be a base address too
  DCHECK_NOT_NULL(mnemonic);
  ResetOutput();
  Substitute(instr, mnemonic);
  if (format != nullptr) {
    buffer_[buffer_pos_++] = ' ';
    Substitute(instr, format);
  }
  buffer_[buffer_pos_] = 0;
  ProcessOutput(instr);
}

void DisassemblingDecoder::Substitute(Instruction* instr, const char* string) {
  char chr = *string++;
  while (chr != '\0') {
    if (chr == '\'') {
      string += SubstituteField(instr, string);
    } else {
      buffer_[buffer_pos_++] = chr;
    }
    chr = *string++;
  }
}

int DisassemblingDecoder::SubstituteField(Instruction* instr,
                                          const char* format) {
  switch (format[0]) {
    // NB. The remaining substitution prefix characters are: GJKUZ.
    case 'R':  // Register. X or W, selected by sf bit.
    case 'F':  // FP register. S or D, selected by type field.
    case 'V':  // Vector register, V, vector format.
    case 'W':
    case 'X':
    case 'B':
    case 'H':
    case 'S':
    case 'D':
    case 'Q':
      return SubstituteRegisterField(instr, format);
    case 'I':
      return SubstituteImmediateField(instr, format);
    case 'L':
      return SubstituteLiteralField(instr, format);
    case 'N':
      return SubstituteShiftField(instr, format);
    case 'P':
      return SubstitutePrefetchField(instr, format);
    case 'C':
      return SubstituteConditionField(instr, format);
    case 'E':
      return SubstituteExtendField(instr, format);
    case 'A':
      return SubstitutePCRelAddressField(instr, format);
    case 'T':
      return SubstituteBranchTargetField(instr, format);
    case 'O':
      return SubstituteLSRegOffsetField(instr, format);
    case 'M':
      return SubstituteBarrierField(instr, format);
    default:
      UNREACHABLE();
  }
}

int DisassemblingDecoder::SubstituteRegisterField(Instruction* instr,
                                                  const char* format) {
  char reg_prefix = format[0];
  unsigned reg_num = 0;
  unsigned field_len = 2;

  switch (format[1]) {
    case 'd':
      reg_num = instr->Rd();
      if (format[2] == 'q') {
        reg_prefix = instr->NEONQ() ? 'X' : 'W';
        field_len = 3;
      }
      break;
    case 'n':
      reg_num = instr->Rn();
      break;
    case 'm':
      reg_num = instr->Rm();
      switch (format[2]) {
        // Handle registers tagged with b (bytes), z (instruction), or
        // r (registers), used for address updates in
        // NEON load/store instructions.
        case 'r':
        case 'b':
        case 'z': {
          field_len = 3;
          char* eimm;
          int imm = static_cast<int>(strtol(&format[3], &eimm, 10));
          field_len += eimm - &format[3];
          if (reg_num == 31) {
            switch (format[2]) {
              case 'z':
                imm *= (1 << instr->NEONLSSize());
                break;
              case 'r':
                imm *= (instr->NEONQ() == 0) ? kDRegSize : kQRegSize;
                break;
              case 'b':
                break;
            }
            AppendToOutput("#%d", imm);
            return field_len;
          }
          break;
        }
      }
      break;
    case 'e':
      // This is register Rm, but using a 4-bit specifier. Used in NEON
      // by-element instructions.
      reg_num = (instr->Rm() & 0xF);
      break;
    case 'a':
      reg_num = instr->Ra();
      break;
    case 't':
      reg_num = instr->Rt();
      if (format[0] == 'V') {
        if ((format[2] >= '2') && (format[2] <= '4')) {
          // Handle consecutive vector register specifiers Vt2, Vt3 and Vt4.
          reg_num = (reg_num + format[2] - '1') % 32;
          field_len = 3;
        }
      } else {
        if (format[2] == '2') {
          // Handle register specifier Rt2.
          reg_num = instr->Rt2();
          field_len = 3;
        }
      }
      break;
    case 's':
      reg_num = instr->Rs();
      break;
    default:
      UNREACHABLE();
  }

  // Increase field length for registers tagged as stack.
  if (format[2] == 's') {
    field_len = 3;
  }

  // W or X registers tagged with '+' have their number incremented, to support
  // instructions such as CASP.
  if (format[2] == '+') {
    DCHECK((reg_prefix == 'W') || (reg_prefix == 'X'));
    reg_num++;
    field_len++;
  }

  CPURegister::RegisterType reg_type;
  unsigned reg_size;

  if (reg_prefix == 'R') {
    reg_prefix = instr->SixtyFourBits() ? 'X' : 'W';
  } else if (reg_prefix == 'F') {
    reg_prefix = ((instr->FPType() & 1) == 0) ? 'S' : 'D';
  }

  switch (reg_prefix) {
    case 'W':
      reg_type = CPURegister::kRegister;
      reg_size = kWRegSizeInBits;
      break;
    case 'X':
      reg_type = CPURegister::kRegister;
      reg_size = kXRegSizeInBits;
      break;
    case 'B':
      reg_type = CPURegister::kVRegister;
      reg_size = kBRegSizeInBits;
      break;
    case 'H':
      reg_type = CPURegister::kVRegister;
      reg_size = kHRegSizeInBits;
      break;
    case 'S':
      reg_type = CPURegister::kVRegister;
      reg_size = kSRegSizeInBits;
      break;
    case 'D':
      reg_type = CPURegister::kVRegister;
      reg_size = kDRegSizeInBits;
      break;
    case 'Q':
      reg_type = CPURegister::kVRegister;
      reg_size = kQRegSizeInBits;
      break;
    case 'V':
      AppendToOutput("v%d", reg_num);
      return field_len;
    default:
      UNREACHABLE();
  }

  if ((reg_type == CPURegister::kRegister) && (reg_num == kZeroRegCode) &&
      (format[2] == 's')) {
    reg_num = kSPRegInternalCode;
  }

  AppendRegisterNameToOutput(CPURegister::Create(reg_num, reg_size, reg_type));

  return field_len;
}

int DisassemblingDecoder::SubstituteImmediateField(Instruction* instr,
                                                   const char* format) {
  DCHECK_EQ(format[0], 'I');

  switch (format[1]) {
    case 'M': {  // IMoveImm or IMoveLSL.
      if (format[5] == 'I' || format[5] == 'N') {
        uint64_t imm = static_cast<uint64_t>(instr->ImmMoveWide())
                       << (16 * instr->ShiftMoveWide());
        if (format[5] == 'N') imm = ~imm;
        if (!instr->SixtyFourBits()) imm &= UINT64_C(0xFFFFFFFF);
        AppendToOutput("#0x%" PRIx64, imm);
      } else {
        DCHECK_EQ(format[5], 'L');
        AppendToOutput("#0x%" PRIx64, instr->ImmMoveWide());
        if (instr->ShiftMoveWide() > 0) {
          AppendToOutput(", lsl #%d", 16 * instr->ShiftMoveWide());
        }
      }
      return 8;
    }
    case 'L': {
      switch (format[2]) {
        case 'L': {  // ILLiteral - Immediate Load Literal.
          AppendToOutput("pc%+" PRId32,
                         instr->ImmLLiteral() * kLoadLiteralScale);
          return 9;
        }
        case 'S': {  // ILS - Immediate Load/Store.
          if (instr->ImmLS() != 0) {
            AppendToOutput(", #%" PRId32, instr->ImmLS());
          }
          return 3;
        }
        case 'P': {  // ILPx - Immediate Load/Store Pair, x = access size.
          if (instr->ImmLSPair() != 0) {
            // format[3] is the scale value. Convert to a number.
            int scale = 1 << (format[3] - '0');
            AppendToOutput(", #%" PRId32, instr->ImmLSPair() * scale);
          }
          return 4;
        }
        case 'U': {  // ILU - Immediate Load/Store Unsigned.
          if (instr->ImmLSUnsigned() != 0) {
            int shift = instr->SizeLS();
            AppendToOutput(", #%" PRId32, instr->ImmLSUnsigned() << shift);
          }
          return 3;
        }
      }
    }
    case 'C': {  // ICondB - Immediate Conditional Branch.
      int64_t offset = instr->ImmCondBranch() << 2;
      char sign = (offset >= 0) ? '+' : '-';
      AppendToOutput("#%c0x%" PRIx64, sign, offset);
      return 6;
    }
    case 'A': {  // IAddSub.
      DCHECK_LE(instr->ShiftAddSub(), 1);
      int64_t imm = instr->ImmAddSub() << (12 * instr->ShiftAddSub());
      AppendToOutput("#0x%" PRIx64 " (%" PRId64 ")", imm, imm);
      return 7;
    }
    case 'F': {                // IFPSingle, IFPDouble or IFPFBits.
      if (format[3] == 'F') {  // IFPFBits.
        AppendToOutput("#%d", 64 - instr->FPScale());
        return 8;
      } else {
        AppendToOutput("#0x%" PRIx32 " (%.4f)", instr->ImmFP(),
                       format[3] == 'S' ? instr->ImmFP32() : instr->ImmFP64());
        return 9;
      }
    }
    case 'T': {  // ITri - Immediate Triangular Encoded.
      AppendToOutput("#0x%" PRIx64, instr->ImmLogical());
      return 4;
    }
    case 'N': {  // INzcv.
      int nzcv = (instr->Nzcv() << Flags_offset);
      AppendToOutput("#%c%c%c%c", ((nzcv & NFlag) == 0) ? 'n' : 'N',
                     ((nzcv & ZFlag) == 0) ? 'z' : 'Z',
                     ((nzcv & CFlag) == 0) ? 'c' : 'C',
                     ((nzcv & VFlag) == 0) ? 'v' : 'V');
      return 5;
    }
    case 'P': {  // IP - Conditional compare.
      AppendToOutput("#%d", instr->ImmCondCmp());
      return 2;
    }
    case 'B': {  // Bitfields.
      return SubstituteBitfieldImmediateField(instr, format);
    }
    case 'E': {  // IExtract.
      AppendToOutput("#%d", instr->ImmS());
      return 8;
    }
    case 'S': {  // IS - Test and branch bit.
      AppendToOutput("#%d", (instr->ImmTestBranchBit5() << 5) |
                                instr->ImmTestBranchBit40());
      return 2;
    }
    case 's': {  // Is - Shift (immediate).
      switch (format[2]) {
        case '1': {  // Is1 - SSHR.
          int shift = 16 << HighestSetBitPosition(instr->ImmNEONImmh());
          shift -= instr->ImmNEONImmhImmb();
          AppendToOutput("#%d", shift);
          return 3;
        }
        case '2': {  // Is2 - SLI.
          int shift = instr->ImmNEONImmhImmb();
          shift -= 8 << HighestSetBitPosition(instr->ImmNEONImmh());
          AppendToOutput("#%d", shift);
          return 3;
        }
        default: {
          UNIMPLEMENTED();
        }
      }
    }
    case 'D': {  // IDebug - HLT and BRK instructions.
      AppendToOutput("#0x%x", instr->ImmException());
      return 6;
    }
    case 'V': {  // Immediate Vector.
      switch (format[2]) {
        case 'E': {  // IVExtract.
          AppendToOutput("#%" PRId64, instr->ImmNEONExt());
          return 9;
        }
        case 'B': {  // IVByElemIndex.
          int vm_index = (instr->NEONH() << 1) | instr->NEONL();
          if (instr->NEONSize() == 1) {
            vm_index = (vm_index << 1) | instr->NEONM();
          }
          AppendToOutput("%d", vm_index);
          return static_cast<int>(strlen("IVByElemIndex"));
        }
        case 'I': {  // INS element.
          if (strncmp(format, "IVInsIndex", strlen("IVInsIndex")) == 0) {
            unsigned rd_index, rn_index;
            unsigned imm5 = instr->ImmNEON5();
            unsigned imm4 = instr->ImmNEON4();
            int tz = base::bits::CountTrailingZeros(imm5);
            if (tz <= 3) {  // Defined for 0 <= tz <= 3 only.
              rd_index = imm5 >> (tz + 1);
              rn_index = imm4 >> tz;
              if (strncmp(format, "IVInsIndex1", strlen("IVInsIndex1")) == 0) {
                AppendToOutput("%d", rd_index);
                return static_cast<int>(strlen("IVInsIndex1"));
              } else if (strncmp(format, "IVInsIndex2",
                                 strlen("IVInsIndex2")) == 0) {
                AppendToOutput("%d", rn_index);
                return static_cast<int>(strlen("IVInsIndex2"));
              }
            }
            return 0;
          }
          UNIMPLEMENTED();
        }
        case 'L': {  // IVLSLane[0123] - suffix indicates access size shift.
          AppendToOutput("%d", instr->NEONLSIndex(format[8] - '0'));
          return 9;
        }
        case 'M': {  // Modified Immediate cases.
          if (strncmp(format, "IVMIImmFPSingle", strlen("IVMIImmFPSingle")) ==
              0) {
            AppendToOutput("#0x%" PRIx32 " (%.4f)", instr->ImmNEONabcdefgh(),
                           instr->ImmNEONFP32());
            return static_cast<int>(strlen("IVMIImmFPSingle"));
          } else if (strncmp(format, "IVMIImmFPDouble",
                             strlen("IVMIImmFPDouble")) == 0) {
            AppendToOutput("#0x%" PRIx32 " (%.4f)", instr->ImmNEONabcdefgh(),
                           instr->ImmNEONFP64());
            return static_cast<int>(strlen("IVMIImmFPDouble"));
          } else if (strncmp(format, "IVMIImm8", strlen("IVMIImm8")) == 0) {
            uint64_t imm8 = instr->ImmNEONabcdefgh();
            AppendToOutput("#0x%" PRIx64, imm8);
            return static_cast<int>(strlen("IVMIImm8"));
          } else if (strncmp(format, "IVMIImm", strlen("IVMIImm")) == 0) {
            uint64_t imm8 = instr->ImmNEONabcdefgh();
            uint64_t imm = 0;
            for (int i = 0; i < 8; ++i) {
              if (imm8 & (1ULL << i)) {
                imm |= (UINT64_C(0xFF) << (8 * i));
              }
            }
            AppendToOutput("#0x%" PRIx64, imm);
            return static_cast<int>(strlen("IVMIImm"));
          } else if (strncmp(format, "IVMIShiftAmt1",
                             strlen("IVMIShiftAmt1")) == 0) {
            int cmode = instr->NEONCmode();
            int shift_amount = 8 * ((cmode >> 1) & 3);
            AppendToOutput("#%d", shift_amount);
            return static_cast<int>(strlen("IVMIShiftAmt1"));
          } else if (strncmp(format, "IVMIShiftAmt2",
                             strlen("IVMIShiftAmt2")) == 0) {
            int cmode = instr->NEONCmode();
            int shift_amount = 8 << (cmode & 1);
            AppendToOutput("#%d", shift_amount);
            return static_cast<int>(strlen("IVMIShiftAmt2"));
          } else {
            UNIMPLEMENTED();
          }
        }
        default: {
          UNIMPLEMENTED();
        }
      }
    }
    default: {
      printf("%s", format);
      UNREACHABLE();
    }
  }
}

int DisassemblingDecoder::SubstituteBitfieldImmediateField(Instruction* instr,
                                                           const char* format) {
  DCHECK((format[0] == 'I') && (format[1] == 'B'));
  unsigned r = instr->ImmR();
  unsigned s = instr->ImmS();

  switch (format[2]) {
    case 'r': {  // IBr.
      AppendToOutput("#%d", r);
      return 3;
    }
    case 's': {  // IBs+1 or IBs-r+1.
      if (format[3] == '+') {
        AppendToOutput("#%d", s + 1);
        return 5;
      } else {
        DCHECK_EQ(format[3], '-');
        AppendToOutput("#%d", s - r + 1);
        return 7;
      }
    }
    case 'Z': {  // IBZ-r.
      DCHECK((format[3] == '-') && (format[4] == 'r'));
      unsigned reg_size =
          (instr->SixtyFourBits() == 1) ? kXRegSizeInBits : kWRegSizeInBits;
      AppendToOutput("#%d", reg_size - r);
      return 5;
    }
    default: {
      UNREACHABLE();
    }
  }
}

int DisassemblingDecoder::SubstituteLiteralField(Instruction* instr,
                                                 const char* format) {
  DCHECK_EQ(strncmp(format, "LValue", 6), 0);
  USE(format);

  switch (instr->Mask(LoadLiteralMask)) {
    case LDR_w_lit:
    case LDR_x_lit:
    case LDR_s_lit:
    case LDR_d_lit:
      AppendToOutput("(addr 0x%016" PRIxPTR ")", instr->LiteralAddress());
      break;
    default:
      UNREACHABLE();
  }

  return 6;
}

int DisassemblingDecoder::SubstituteShiftField(Instruction* instr,
                                               const char* format) {
  DCHECK_EQ(format[0], 'N');
  DCHECK_LE(instr->ShiftDP(), 0x3);

  switch (format[1]) {
    case 'D': {  // NDP.
      DCHECK(instr->ShiftDP() != ROR);
      [[fallthrough]];
    }
    case 'L': {  // NLo.
      if (instr->ImmDPShift() != 0) {
        const char* shift_type[] = {"lsl", "lsr", "asr", "ror"};
        AppendToOutput(", %s #%" PRId32, shift_type[instr->ShiftDP()],
                       instr->ImmDPShift());
      }
      return 3;
    }
    default:
      UNREACHABLE();
  }
}

int DisassemblingDecoder::SubstituteConditionField(Instruction* instr,
                                                   const char* format) {
  DCHECK_EQ(format[0], 'C');
  const char* condition_code[] = {"eq", "ne", "hs", "lo", "mi", "pl",
                                  "vs", "vc", "hi", "ls", "ge", "lt",
                                  "gt", "le", "al", "nv"};
  int cond;
  switch (format[1]) {
    case 'B':
      cond = instr->ConditionBranch();
      break;
    case 'I': {
      cond = NegateCondition(static_cast<Condition>(instr->Condition()));
      break;
    }
    default:
      cond = instr->Condition();
  }
  AppendToOutput("%s", condition_code[cond]);
  return 4;
}

int DisassemblingDecoder::SubstitutePCRelAddressField(Instruction* instr,
                                                      const char* format) {
  USE(format);
  DCHECK_EQ(strncmp(format, "AddrPCRel", 9), 0);

  int offset = instr->ImmPCRel();

  // Only ADR (AddrPCRelByte) is supported.
  DCHECK_EQ(strcmp(format, "AddrPCRelByte"), 0);

  char sign = '+';
  if (offset < 0) {
    sign = '-';
  }
  AppendToOutput("#%c0x%x (addr %p)", sign, Abs(offset),
                 instr->InstructionAtOffset(offset, Instruction::NO_CHECK));
  return 13;
}

int DisassemblingDecoder::SubstituteBranchTargetField(Instruction* instr,
                                                      const char* format) {
  DCHECK_EQ(strncmp(format, "TImm", 4), 0);

  int64_t offset = 0;
  switch (format[5]) {
    // TImmUncn - unconditional branch immediate.
    case 'n':
      offset = instr->ImmUncondBranch();
      break;
    // TImmCond - conditional branch immediate.
    case 'o':
      offset = instr->ImmCondBranch();
      break;
    // TImmCmpa - compare and branch immediate.
    case 'm':
      offset = instr->ImmCmpBranch();
      break;
    // TImmTest - test and branch immediate.
    case 'e':
      offset = instr->ImmTestBranch();
      break;
    default:
      UNREACHABLE();
  }
  offset *= kInstrSize;
  char sign = '+';
  if (offset < 0) {
    sign = '-';
  }
  AppendToOutput("#%c0x%" PRIx64 " (addr %p)", sign, Abs(offset),
                 instr->InstructionAtOffset(offset), Instruction::NO_CHECK);
  return 8;
}

int DisassemblingDecoder::SubstituteExtendField(Instruction* instr,
                                                const char* format) {
  DCHECK_EQ(strncmp(format, "Ext", 3), 0);
  DCHECK_LE(instr->ExtendMode(), 7);
  USE(format);

  const char* extend_mode[] = {"uxtb", "uxth", "uxtw", "uxtx",
                               "sxtb", "sxth", "sxtw", "sxtx"};

  // If rd or rn is SP, uxtw on 32-bit registers and uxtx on 64-bit
  // registers becomes lsl.
  if (((instr->Rd() == kZeroRegCode) || (instr->Rn() == kZeroRegCode)) &&
      (((instr->ExtendMode() == UXTW) && (instr->SixtyFourBits() == 0)) ||
       (instr->ExtendMode() == UXTX))) {
    if (instr->ImmExtendShift() > 0) {
      AppendToOutput(", lsl #%d", instr->ImmExtendShift());
    }
  } else {
    AppendToOutput(", %s", extend_mode[instr->ExtendMode()]);
    if (instr->ImmExtendShift() > 0) {
      AppendToOutput(" #%d", instr->ImmExtendShift());
    }
  }
  return 3;
}

int DisassemblingDecoder::SubstituteLSRegOffsetField(Instruction* instr,
                                                     const char* format) {
  DCHECK_EQ(strncmp(format, "Offsetreg", 9), 0);
  const char* extend_mode[] = {"undefined", "undefined", "uxtw", "lsl",
                               "undefined", "undefined", "sxtw", "sxtx"};
  USE(format);

  unsigned shift = instr->ImmShiftLS();
  Extend ext = static_cast<Extend>(instr->ExtendMode());
  char reg_type = ((ext == UXTW) || (ext == SXTW)) ? 'w' : 'x';

  unsigned rm = instr->Rm();
  if (rm == kZeroRegCode) {
    AppendToOutput("%czr", reg_type);
  } else {
    AppendToOutput("%c%d", reg_type, rm);
  }

  // Extend mode UXTX is an alias for shift mode LSL here.
  if (!((ext == UXTX) && (shift == 0))) {
    AppendToOutput(", %s", extend_mode[ext]);
    if (shift != 0) {
      AppendToOutput(" #%d", instr->SizeLS());
    }
  }
  return 9;
}

int DisassemblingDecoder::SubstitutePrefetchField(Instruction* instr,
                                                  const char* format) {
  DCHECK_EQ(format[0], 'P');
  USE(format);

  int prefetch_mode = instr->PrefetchMode();

  const char* ls = (prefetch_mode & 0x10) ? "st" : "ld";
  int level = (prefetch_mode >> 1) + 1;
  const char* ks = (prefetch_mode & 1) ? "strm" : "keep";

  AppendToOutput("p%sl%d%s", ls, level, ks);
  return 6;
}

int DisassemblingDecoder::SubstituteBarrierField(Instruction* instr,
                                                 const char* format) {
  DCHECK_EQ(format[0], 'M');
  USE(format);

  static const char* const options[4][4] = {
      {"sy (0b0000)", "oshld", "oshst", "osh"},
      {"sy (0b0100)", "nshld", "nshst", "nsh"},
      {"sy (0b1000)", "ishld", "ishst", "ish"},
      {"sy (0b1100)", "ld", "st", "sy"}};
  int domain = instr->ImmBarrierDomain();
  int type = instr->ImmBarrierType();

  AppendToOutput("%s", options[domain][type]);
  return 1;
}

void DisassemblingDecoder::ResetOutput() {
  buffer_pos_ = 0;
  buffer_[buffer_pos_] = 0;
}

void DisassemblingDecoder::AppendToOutput(const char* format, ...) {
  va_list args;
  va_start(args, format);
  buffer_pos_ += vsnprintf(&buffer_[buffer_pos_], buffer_size_, format, args);
  va_end(args);
}

void DisassemblingDecoder::DisassembleNEONPolynomialMul(Instruction* instr) {
  int q = instr->Bit(30);
  const char* mnemonic = q ? "pmull2" : "pmull";
  const char* form = NULL;
  int size = instr->NEONSize();
  if (size == 0) {
    if (q == 0) {
      form = "'Vd.8h, 'Vn.8b, 'Vm.8b";
    } else {
      form = "'Vd.8h, 'Vn.16b, 'Vm.16b";
    }
  } else if (size == 3) {
    if (q == 0) {
      form = "'Vd.1q, 'Vn.1d, 'Vm.1d";
    } else {
      form = "'Vd.1q, 'Vn.2d, 'Vm.2d";
    }
  } else {
    mnemonic = "undefined";
  }
  Format(instr, mnemonic, form);
}

void PrintDisassembler::ProcessOutput(Instruction* instr) {
  fprintf(stream_, "0x%016" PRIx64 "  %08" PRIx32 "\t\t%s\n",
          reinterpret_cast<uint64_t>(instr), instr->InstructionBits(),
          GetOutput());
}

}  // namespace internal
}  // namespace v8

namespace disasm {

const char* NameConverter::NameOfAddress(uint8_t* addr) const {
  v8::base::SNPrintF(tmp_buffer_, "%p", static_cast<void*>(addr));
  return tmp_buffer_.begin();
}

const char* NameConverter::NameOfConstant(uint8_t* addr) const {
  return NameOfAddress(addr);
}

const char* NameConverter::NameOfCPURegister(int reg) const {
  unsigned ureg = reg;  // Avoid warnings about signed/unsigned comparisons.
  if (ureg >= v8::internal::kNumberOfRegisters) {
    return "noreg";
  }
  if (ureg == v8::internal::kZeroRegCode) {
    return "xzr";
  }
  v8::base::SNPrintF(tmp_buffer_, "x%u", ureg);
  return tmp_buffer_.begin();
}

const char* NameConverter::NameOfByteCPURegister(int reg) const {
  UNREACHABLE();  // ARM64 does not have the concept of a byte register
}

const char* NameConverter::NameOfXMMRegister(int reg) const {
  UNREACHABLE();  // ARM64 does not have any XMM registers
}

const char* NameConverter::NameInCode(uint8_t* addr) const {
  // The default name converter is called for unknown code, so we will not try
  // to access any memory.
  return "";
}

//------------------------------------------------------------------------------

class BufferDisassembler : public v8::internal::DisassemblingDecoder {
 public:
  explicit BufferDisassembler(v8::base::Vector<char> out_buffer)
      : out_buffer_(out_buffer) {}

  ~BufferDisassembler() {}

  virtual void ProcessOutput(v8::internal::Instruction* instr) {
    v8::base::SNPrintF(out_buffer_, "%08" PRIx32 "       %s",
                       instr->InstructionBits(), GetOutput());
  }

 private:
  v8::base::Vector<char> out_buffer_;
};

int Disassembler::InstructionDecode(v8::base::Vector<char> buffer,
                                    uint8_t* instr) {
  USE(converter_);  // avoid unused field warning
  v8::internal::Decoder<v8::internal::DispatchingDecoderVisitor> decoder;
  BufferDisassembler disasm(buffer);
  decoder.AppendVisitor(&disasm);

  decoder.Decode(reinterpret_cast<v8::internal::Instruction*>(instr));
  return v8::internal::kInstrSize;
}

int Disassembler::ConstantPoolSizeAt(uint8_t* instr) {
  return v8::internal::Assembler::ConstantPoolSizeAt(
      reinterpret_cast<v8::internal::Instruction*>(instr));
}

void Disassembler::Disassemble(FILE* file, uint8_t* start, uint8_t* end,
                               UnimplementedOpcodeAction) {
  v8::internal::Decoder<v8::internal::DispatchingDecoderVisitor> decoder;
  v8::internal::PrintDisassembler disasm(file);
  decoder.AppendVisitor(&disasm);

  for (uint8_t* pc = start; pc < end; pc += v8::internal::kInstrSize) {
    decoder.Decode(reinterpret_cast<v8::internal::Instruction*>(pc));
  }
}

}  // namespace disasm

#endif  // V8_TARGET_ARCH_ARM64

"""


```