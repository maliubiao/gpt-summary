Response:
Let's break down the thought process for analyzing this ARM64 assembler test code.

**1. Understanding the Goal:**

The primary goal is to understand the *functionality* of the provided C++ code snippet. It's explicitly stated that this is part of V8's test suite, specifically for the ARM64 assembler. This immediately tells us it's testing low-level code generation.

**2. Initial Scan for Keywords and Patterns:**

I'd quickly scan the code for recognizable patterns and keywords related to testing and assembly. Here's what stands out:

* **`TEST(...) { ... }`:** This clearly indicates individual test cases. Each `TEST` block focuses on a specific aspect of the assembler.
* **`INIT_V8();` and `SETUP();`:** These are likely boilerplate setup functions common in V8's testing framework.
* **`__ Mov(...)`, `__ Ldp(...)`, `__ Stp(...)`, `__ Ldr(...)`, `__ Str(...)`, `__ Add(...)`, `__ Sub(...)`, `__ Neg(...)`, `__ Adcs(...)`, `__ Sbcs(...)`:** These are the core of the code. The `__` prefix suggests they are methods of an assembler class (likely `MacroAssembler`). The names themselves are strong hints about ARM64 instructions: Move, Load Pair, Store Pair, Load Register, Store Register, Add, Subtract, Negate, Add with Carry, Subtract with Carry.
* **`MemOperand(...)`:** This is used in conjunction with load and store instructions, indicating memory access.
* **`PostIndex`:**  Appearing in `Ldp` and `Stp` tests, indicating post-increment/decrement addressing modes.
* **`CHECK_EQUAL_64(...)`, `CHECK_EQUAL_32(...)`, `CHECK_FULL_HEAP_OBJECT_IN_REGISTER(...)`, `CHECK_EQ(...)`, `CHECK(...)`, `CHECK_NE(...)`, `CHECK_EQUAL_NZCV(...)`:** These are assertion macros used to verify the expected outcomes of the assembly code. They compare register values, memory contents, and processor flags against expected values.
* **`START();` and `END();` and `RUN();`:**  These likely demarcate the assembly code block within the test and the execution of that code.
* **`isolate->factory()->...`:**  This suggests interaction with V8's object creation mechanism, particularly in tests involving loading literals.
* **`LiteralPoolEmitOutcome`, `LiteralPoolEmissionAlignment`:** These enums are specific to testing the emission of literal pools (constant data embedded in the code).
* **`kInt64Size`, `kInt32Size`, `kInstrSize`:** These constants represent the sizes of data types and instructions, crucial for understanding memory layouts and offsets.
* **Code comments:** Though not extensive, the comments provide brief explanations of what certain tests are doing (e.g., "Move base too far from the array to force multiple instructions to be emitted.").

**3. Deconstructing Individual Tests:**

Now, I'd go through each `TEST` case, focusing on:

* **The name of the test:** This often gives a strong clue about the instruction(s) being tested (e.g., `ldp_stp_preindex`).
* **The setup:** What data structures (arrays, variables) are initialized?
* **The assembly code:** What ARM64 instructions are being used, and with what operands (registers, memory locations, immediate values)?
* **The assertions:** What values are being checked, and what do those checks imply about the behavior of the executed assembly?

**4. Identifying Functionality (Iterative Process):**

By examining the instructions and assertions in each test, I can start to build a picture of the file's overall functionality. For example:

* Tests with `Ldp` and `Stp` are clearly about testing load and store pair instructions, both with pre- and post-indexing.
* Tests with `Ldr` and `Str` are about testing individual load and store instructions.
* Tests with `Add`, `Sub`, and `Neg` are about arithmetic operations.
* Tests with `Adcs` and `Sbcs` are about arithmetic with carry.
* Tests involving `isolate->factory()` and `Ldr` are about loading literal values from the constant pool.

**5. Addressing Specific Requirements:**

Once I have a general understanding, I address the specific instructions in the prompt:

* **`.tq` check:**  The filename ends in `.cc`, not `.tq`, so it's not a Torque file.
* **JavaScript relationship:**  The code tests the *assembler*, which is a low-level component used by V8 to generate machine code for JavaScript. A simple JavaScript example that would eventually use this assembler is basic arithmetic or variable assignment.
* **Code logic and assumptions:**  For tests like `ldp_stp_preindex`, I can trace the register and memory manipulations step-by-step, noting the initial values and the expected changes based on the instructions and addressing modes. For instance, in the pre-index example, the register is modified *before* the memory access.
* **Common programming errors:** Tests involving memory access and offsets naturally point to potential errors like out-of-bounds access or incorrect address calculations. The wide immediate tests highlight the complexity of handling larger offsets.
* **Overall function:**  Summarize the individual test functionalities into a concise description of the file's purpose.

**6. Self-Correction and Refinement:**

Throughout the process, I might need to revisit earlier assumptions or interpretations. For example, if an assertion fails to make sense based on my current understanding of an instruction, I'd need to double-check the ARM64 documentation or re-examine the surrounding code. The comments within the code itself are valuable for this refinement.

This iterative process of scanning, deconstructing, and synthesizing allows me to arrive at a comprehensive understanding of the test file's functionality.
This C++ code file, `v8/test/cctest/test-assembler-arm64.cc`, is a crucial part of the V8 JavaScript engine's testing infrastructure. Specifically, it contains **unit tests for the ARM64 assembler**. This means it directly tests the functionality of the code that generates ARM64 machine instructions.

Here's a breakdown of its functions based on the provided snippets:

**Core Functionality:**

* **Testing ARM64 Instructions:** The file contains numerous individual tests (using the `TEST()` macro) that verify the correct behavior of various ARM64 assembly instructions. These tests cover:
    * **Load and Store Instructions:**
        * `ldp` (Load Pair) and `stp` (Store Pair):  Tests loading and storing pairs of registers from/to memory, with different addressing modes (pre-index, post-index, immediate offset). It also tests both 32-bit (`w` registers) and 64-bit (`x` registers) versions.
        * `ldur` (Load Register Unscaled) and `stur` (Store Register Unscaled): Tests loading and storing individual registers with unscaled immediate offsets. It also tests byte-level loads and stores (`ldrb`, `strb`).
        * `ldr` (Load Register): Tests loading register values, including loading literals from the constant pool (embedded data in the generated code) and PC-relative addressing for larger offsets. It specifically tests the mechanism for emitting and managing the literal pool.
        * `ldpsw` (Load Pair Signed Word): Tests loading a pair of 32-bit values and sign-extending them to 64-bit.
    * **Arithmetic and Logical Instructions:**
        * `add` (Add) and `sub` (Subtract): Tests addition and subtraction with immediate values (both narrow and wide), shifted register operands, and extended register operands. It also tests adding and subtracting negative immediates and the behavior when adding or subtracting zero.
        * `neg` (Negate): Tests negating values using immediate, shifted, and extended register operands.
        * `adcs` (Add with Carry) and `sbcs` (Subtract with Carry): Tests arithmetic operations that incorporate the carry flag from previous operations.
        * `and` (Logical AND), `orr` (Logical OR), `eor` (Logical XOR): These are briefly mentioned in the `preshift_immediates` test.
    * **Stack Manipulation:**
        * `claim` and `drop`: Tests allocating and deallocating space on the stack.
    * **Immediate Handling:**  Tests how the assembler handles different forms of immediate values, including those requiring pre-shifting.

* **Verifying Instruction Encoding and Execution:**  Each test case sets up specific input conditions (register values, memory contents), executes a sequence of assembler instructions using the `MacroAssembler` class (indicated by `__`), and then uses `CHECK_EQUAL_*` macros to assert that the resulting register values, memory contents, and processor flags are as expected.

* **Testing Literal Pool Management:** Several tests specifically focus on the assembler's ability to emit and manage the literal pool. This involves ensuring that constants are placed in the code at an accessible distance and that the assembler handles cases where the pool needs to be emitted at specific points to remain within reach of `ldr` instructions.

**Relationship to JavaScript:**

This code directly underpins the performance of JavaScript code execution in V8 on ARM64 architectures. When V8 compiles JavaScript code, it uses the assembler (the code being tested here) to translate the high-level JavaScript operations into low-level ARM64 machine instructions that the processor can understand and execute. For example:

```javascript
// Simple JavaScript addition
let a = 10;
let b = 5;
let sum = a + b;
```

Internally, V8's compiler would use the ARM64 assembler (and the code being tested in this file) to generate ARM64 `add` instructions to perform the `a + b` operation. The tests in `test-assembler-arm64.cc` ensure that this generation of `add` instructions (and other instructions) is correct under various conditions.

**Code Logic and Assumptions (Example: `ldp_stp_preindex`)**

Let's take the `ldp_stp_preindex` test as an example:

**Assumptions:**

* We have an array `src` of four 64-bit integers.
* We have an array `dst` of five 64-bit integers, initialized to zero.
* We have registers `x24` and `x25` holding the base addresses of `src` and `dst`, respectively.
* We have registers to store intermediate results (like `x0`, `x1`, etc.).

**Input:**

* `src`: `{0x0011223344556677UL, 0x8899AABBCCDDEEFFUL, 0xFFEEDDCCBBAA9988UL, 0x7766554433221100UL}`
* `dst`: `{0, 0, 0, 0, 0}`
* `x24` (src_base): Address of the beginning of `src`.
* `x25` (dst_base): Address of the beginning of `dst`.
* `x28` (dst_base + 16): Address of `dst[2]`.

**Assembly Logic:**

1. `__ Ldp(w0, w1, MemOperand(x24, 4, PreIndex));`: Load two 32-bit words from memory starting at `src_base + 4`. **Crucially, `PreIndex` means the base register `x24` is updated *before* the load.** So, `x24` becomes `src_base + 4`, and `w0` gets the lower 32 bits of `src[0]` (0x44556677), and `w1` gets the lower 32 bits of `src[1]` (0xCCDDEEFF).
2. `__ Mov(x19, x24);`: Copy the updated `x24` (which is now `src_base + 4`) to `x19`.
3. `__ Stp(w0, w1, MemOperand(x25, 4, PreIndex));`: Store the 32-bit values in `w0` and `w1` to memory starting at `dst_base + 4`. Again, `PreIndex` updates `x25` to `dst_base + 4` before the store.
4. Subsequent `Ldp` and `Stp` instructions follow a similar pattern, loading and storing pairs of 32-bit or 64-bit values, updating the base registers accordingly.

**Output (Assertions):**

The `CHECK_EQUAL_*` macros verify that:

* The registers `x0` to `x7` hold the expected loaded values.
* The `dst` array has been modified correctly by the store operations.
* The base registers (`x24`, `x25`, `x28`) have been updated as expected by the pre-indexing.
* The intermediate registers (`x19`, `x20`, `x21`, `x22`) hold the expected base addresses at specific points.

**Common Programming Errors (Related to this File):**

This type of testing directly helps catch common errors that developers might make when writing assembly code or the code that generates assembly:

* **Incorrect Offset Calculations:**  Mistakes in calculating the offset for memory access can lead to reading or writing to the wrong memory locations. The tests with various offsets (positive, negative, wide) help ensure these calculations are correct in the assembler.
* **Incorrect Addressing Modes:** Using pre-index when post-index is intended (or vice-versa) will lead to unexpected base register updates and memory accesses. The tests explicitly for pre-index and post-index modes help prevent these errors.
* **Register Allocation Errors:**  Incorrectly using registers for intermediate values or overwriting registers prematurely can lead to incorrect results. The tests verify the expected values in specific registers after instruction execution.
* **Endianness Issues (though less common on ARM64):** While ARM64 is generally little-endian, understanding how multi-byte values are loaded and stored is important.
* **Literal Pool Management Issues:** Forgetting to emit the literal pool or emitting it too far away from the `ldr` instruction can cause runtime errors. The dedicated literal pool tests are crucial for this.
* **Incorrect Flag Handling:**  For instructions that set processor flags (like `adds`, `subs`, `adcs`, `sbcs`), failing to update or use the flags correctly can lead to incorrect conditional branching or later arithmetic operations. The `CHECK_EQUAL_NZCV` macro verifies the correct flag settings.

**If `v8/test/cctest/test-assembler-arm64.cc` ended with `.tq`:**

If the filename ended with `.tq`, it would indicate a **Torque** source file. Torque is V8's internal language for specifying built-in functions and low-level runtime code. Torque code is compiled into C++ code, which is then compiled into machine code. In this case, the file would likely contain Torque definitions for ARM64-specific runtime functions or helper routines.

**Summary of Functionality (Part 7 of 15):**

As part 7 of 15, this file likely focuses on a specific subset of ARM64 instructions and assembler functionalities. Based on the provided snippets, this section seems heavily focused on:

* **Load and Store instructions (both single and pairs) with various addressing modes.**
* **Basic arithmetic and logical operations with different operand types (immediate, shifted, extended).**
* **Testing the assembler's ability to manage and emit the literal pool for constant values.**
* **Potentially setting the stage for more complex instructions or control flow testing in later parts.**

The tests are designed to be comprehensive, covering various edge cases and combinations of operands to ensure the ARM64 assembler in V8 is robust and generates correct machine code.

Prompt: 
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-assembler-arm64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共15部分，请归纳一下它的功能

"""
9AABBCCDDEEFFUL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base, x24);
  CHECK_EQUAL_64(dst_base, x25);
  CHECK_EQUAL_64(dst_base + 16, x28);
  CHECK_EQUAL_64(src_base + 4, x19);
  CHECK_EQUAL_64(dst_base + 4, x20);
  CHECK_EQUAL_64(src_base + 8, x21);
  CHECK_EQUAL_64(dst_base + 24, x22);
}

TEST(ldp_stp_postindex) {
  INIT_V8();
  SETUP();

  uint64_t src[4] = {0x0011223344556677UL, 0x8899AABBCCDDEEFFUL,
                     0xFFEEDDCCBBAA9988UL, 0x7766554433221100UL};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x16, src_base);
  __ Mov(x17, dst_base);
  __ Mov(x28, dst_base + 16);
  __ Ldp(w0, w1, MemOperand(x16, 4, PostIndex));
  __ Mov(x19, x16);
  __ Ldp(w2, w3, MemOperand(x16, -4, PostIndex));
  __ Stp(w2, w3, MemOperand(x17, 4, PostIndex));
  __ Mov(x20, x17);
  __ Stp(w0, w1, MemOperand(x17, -4, PostIndex));
  __ Ldp(x4, x5, MemOperand(x16, 8, PostIndex));
  __ Mov(x21, x16);
  __ Ldp(x6, x7, MemOperand(x16, -8, PostIndex));
  __ Stp(x7, x6, MemOperand(x28, 8, PostIndex));
  __ Mov(x22, x28);
  __ Stp(x5, x4, MemOperand(x28, -8, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0x4455667700112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x0011223344556677UL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x5);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x6);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base, x16);
  CHECK_EQUAL_64(dst_base, x17);
  CHECK_EQUAL_64(dst_base + 16, x28);
  CHECK_EQUAL_64(src_base + 4, x19);
  CHECK_EQUAL_64(dst_base + 4, x20);
  CHECK_EQUAL_64(src_base + 8, x21);
  CHECK_EQUAL_64(dst_base + 24, x22);
}

TEST(ldp_stp_postindex_wide) {
  INIT_V8();
  SETUP();

  uint64_t src[4] = {0x0011223344556677, 0x8899AABBCCDDEEFF, 0xFFEEDDCCBBAA9988,
                     0x7766554433221100};
  uint64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
  // Move base too far from the array to force multiple instructions
  // to be emitted.
  const int64_t base_offset = 1024;

  START();
  __ Mov(x24, src_base);
  __ Mov(x25, dst_base);
  __ Mov(x28, dst_base + 16);
  __ Ldp(w0, w1, MemOperand(x24, base_offset + 4, PostIndex));
  __ Mov(x19, x24);
  __ Sub(x24, x24, base_offset);
  __ Ldp(w2, w3, MemOperand(x24, base_offset - 4, PostIndex));
  __ Stp(w2, w3, MemOperand(x25, 4 - base_offset, PostIndex));
  __ Mov(x20, x25);
  __ Sub(x24, x24, base_offset);
  __ Add(x25, x25, base_offset);
  __ Stp(w0, w1, MemOperand(x25, -4 - base_offset, PostIndex));
  __ Ldp(x4, x5, MemOperand(x24, base_offset + 8, PostIndex));
  __ Mov(x21, x24);
  __ Sub(x24, x24, base_offset);
  __ Ldp(x6, x7, MemOperand(x24, base_offset - 8, PostIndex));
  __ Stp(x7, x6, MemOperand(x28, 8 - base_offset, PostIndex));
  __ Mov(x22, x28);
  __ Add(x28, x28, base_offset);
  __ Stp(x5, x4, MemOperand(x28, -8 - base_offset, PostIndex));
  END();

  RUN();

  CHECK_EQUAL_64(0x44556677, x0);
  CHECK_EQUAL_64(0x00112233, x1);
  CHECK_EQUAL_64(0x00112233, x2);
  CHECK_EQUAL_64(0xCCDDEEFF, x3);
  CHECK_EQUAL_64(0x4455667700112233UL, dst[0]);
  CHECK_EQUAL_64(0x0000000000112233UL, dst[1]);
  CHECK_EQUAL_64(0x0011223344556677UL, x4);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x5);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, x6);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, x7);
  CHECK_EQUAL_64(0xFFEEDDCCBBAA9988UL, dst[2]);
  CHECK_EQUAL_64(0x8899AABBCCDDEEFFUL, dst[3]);
  CHECK_EQUAL_64(0x0011223344556677UL, dst[4]);
  CHECK_EQUAL_64(src_base + base_offset, x24);
  CHECK_EQUAL_64(dst_base - base_offset, x25);
  CHECK_EQUAL_64(dst_base - base_offset + 16, x28);
  CHECK_EQUAL_64(src_base + base_offset + 4, x19);
  CHECK_EQUAL_64(dst_base - base_offset + 4, x20);
  CHECK_EQUAL_64(src_base + base_offset + 8, x21);
  CHECK_EQUAL_64(dst_base - base_offset + 24, x22);
}

TEST(ldp_sign_extend) {
  INIT_V8();
  SETUP();

  uint32_t src[2] = {0x80000000, 0x7FFFFFFF};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);

  START();
  __ Mov(x24, src_base);
  __ Ldpsw(x0, x1, MemOperand(x24));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFF80000000UL, x0);
  CHECK_EQUAL_64(0x000000007FFFFFFFUL, x1);
}

TEST(ldur_stur) {
  INIT_V8();
  SETUP();

  int64_t src[2] = {0x0123456789ABCDEFUL, 0x0123456789ABCDEFUL};
  int64_t dst[5] = {0, 0, 0, 0, 0};
  uintptr_t src_base = reinterpret_cast<uintptr_t>(src);
  uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);

  START();
  __ Mov(x17, src_base);
  __ Mov(x28, dst_base);
  __ Mov(x19, src_base + 16);
  __ Mov(x20, dst_base + 32);
  __ Mov(x21, dst_base + 40);
  __ Ldr(w0, MemOperand(x17, 1));
  __ Str(w0, MemOperand(x28, 2));
  __ Ldr(x1, MemOperand(x17, 3));
  __ Str(x1, MemOperand(x28, 9));
  __ Ldr(w2, MemOperand(x19, -9));
  __ Str(w2, MemOperand(x20, -5));
  __ Ldrb(w3, MemOperand(x19, -1));
  __ Strb(w3, MemOperand(x21, -1));
  END();

  RUN();

  CHECK_EQUAL_64(0x6789ABCD, x0);
  CHECK_EQUAL_64(0x6789ABCD0000L, dst[0]);
  CHECK_EQUAL_64(0xABCDEF0123456789L, x1);
  CHECK_EQUAL_64(0xCDEF012345678900L, dst[1]);
  CHECK_EQUAL_64(0x000000AB, dst[2]);
  CHECK_EQUAL_64(0xABCDEF01, x2);
  CHECK_EQUAL_64(0x00ABCDEF01000000L, dst[3]);
  CHECK_EQUAL_64(0x00000001, x3);
  CHECK_EQUAL_64(0x0100000000000000L, dst[4]);
  CHECK_EQUAL_64(src_base, x17);
  CHECK_EQUAL_64(dst_base, x28);
  CHECK_EQUAL_64(src_base + 16, x19);
  CHECK_EQUAL_64(dst_base + 32, x20);
}

TEST(ldr_pcrel_large_offset) {
  INIT_V8();
  SETUP_SIZE(1 * MB);

  START();

  __ Ldr(x1, isolate->factory()->undefined_value());

  {
    v8::internal::PatchingAssembler::BlockPoolsScope scope(&masm);
    int start = __ pc_offset();
    while (__ pc_offset() - start < 600 * KB) {
      __ Nop();
    }
  }

  __ Ldr(x2, isolate->factory()->undefined_value());

  END();

  RUN();

  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x1);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x2);
}

TEST(ldr_literal) {
  INIT_V8();
  SETUP();

  START();
  __ Ldr(x2, isolate->factory()->undefined_value());

  END();

  RUN();

  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x2);
}

#ifdef DEBUG
// These tests rely on functions available in debug mode.
enum LiteralPoolEmitOutcome { EmitExpected, NoEmitExpected };
enum LiteralPoolEmissionAlignment { EmitAtUnaligned, EmitAtAligned };

static void LdrLiteralRangeHelper(
    size_t range, LiteralPoolEmitOutcome outcome,
    LiteralPoolEmissionAlignment unaligned_emission) {
  SETUP_SIZE(static_cast<int>(range + 1024));

  const size_t first_pool_entries = 2;
  const size_t first_pool_size_bytes = first_pool_entries * kInt64Size;

  START();
  // Force a pool dump so the pool starts off empty.
  __ ForceConstantPoolEmissionWithJump();
  CHECK_CONSTANT_POOL_SIZE(0);

  // Emit prepadding to influence alignment of the pool.
  bool currently_aligned = IsAligned(__ pc_offset(), kInt64Size);
  if ((unaligned_emission == EmitAtUnaligned && currently_aligned) ||
      (unaligned_emission == EmitAtAligned && !currently_aligned)) {
    __ Nop();
  }

  int initial_pc_offset = __ pc_offset();
  __ Ldr(x0, isolate->factory()->undefined_value());
  __ Ldr(x1, isolate->factory()->the_hole_value());
  CHECK_CONSTANT_POOL_SIZE(first_pool_size_bytes);

  size_t expected_pool_size = 0;

  auto PoolSizeAt = [&](int pc_offset) {
    // To determine padding, consider the size of the prologue of the pool,
    // and the jump around the pool, which we always need.
    size_t prologue_size = 2 * kInstrSize + kInstrSize;
    size_t pc = pc_offset + prologue_size;
    const size_t padding = IsAligned(pc, kInt64Size) ? 0 : kInt32Size;
    CHECK_EQ(padding == 0, unaligned_emission == EmitAtAligned);
    return prologue_size + first_pool_size_bytes + padding;
  };

  int pc_offset_before_emission = -1;
  bool pool_was_emitted = false;
  while (__ pc_offset() - initial_pc_offset < static_cast<intptr_t>(range)) {
    pc_offset_before_emission = __ pc_offset() + kInstrSize;
    __ Nop();
    if (__ GetConstantPoolEntriesSizeForTesting() == 0) {
      pool_was_emitted = true;
      break;
    }
  }

  if (outcome == EmitExpected) {
    if (!pool_was_emitted) {
      FATAL(
          "Pool was not emitted up to pc_offset %d which corresponds to a "
          "distance to the first constant of %d bytes",
          __ pc_offset(), __ pc_offset() - initial_pc_offset);
    }
    // Check that the size of the emitted constant pool is as expected.
    expected_pool_size = PoolSizeAt(pc_offset_before_emission);
    CHECK_EQ(pc_offset_before_emission + expected_pool_size, __ pc_offset());
  } else {
    CHECK_EQ(outcome, NoEmitExpected);
    if (pool_was_emitted) {
      FATAL("Pool was unexpectedly emitted at pc_offset %d ",
            pc_offset_before_emission);
    }
    CHECK_CONSTANT_POOL_SIZE(first_pool_size_bytes);
    CHECK_EQ(pc_offset_before_emission, __ pc_offset());
  }

  // Force a pool flush to check that a second pool functions correctly.
  __ ForceConstantPoolEmissionWithJump();
  CHECK_CONSTANT_POOL_SIZE(0);

  // These loads should be after the pool (and will require a new one).
  const int second_pool_entries = 2;
  __ Ldr(x4, isolate->factory()->true_value());
  __ Ldr(x5, isolate->factory()->false_value());
  CHECK_CONSTANT_POOL_SIZE(second_pool_entries * kInt64Size);

  END();

  if (outcome == EmitExpected) {
    Address pool_start = code->instruction_start() + pc_offset_before_emission;
    Instruction* branch = reinterpret_cast<Instruction*>(pool_start);
    CHECK(branch->IsImmBranch());
    CHECK_EQ(expected_pool_size, branch->ImmPCOffset());
    Instruction* marker =
        reinterpret_cast<Instruction*>(pool_start + kInstrSize);
    CHECK(marker->IsLdrLiteralX());
    size_t pool_data_start_offset = pc_offset_before_emission + kInstrSize;
    size_t padding =
        IsAligned(pool_data_start_offset, kInt64Size) ? 0 : kInt32Size;
    size_t marker_size = kInstrSize;
    CHECK_EQ((first_pool_size_bytes + marker_size + padding) / kInt32Size,
             marker->ImmLLiteral());
  }

  RUN();

  // Check that the literals loaded correctly.
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->undefined_value(), x0);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->the_hole_value(), x1);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->true_value(), x4);
  CHECK_FULL_HEAP_OBJECT_IN_REGISTER(isolate->factory()->false_value(), x5);
}

TEST(ldr_literal_range_max_dist_emission_1) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() +
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      EmitExpected, EmitAtAligned);
}

TEST(ldr_literal_range_max_dist_emission_2) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() +
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      EmitExpected, EmitAtUnaligned);
}

TEST(ldr_literal_range_max_dist_no_emission_1) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() -
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      NoEmitExpected, EmitAtUnaligned);
}

TEST(ldr_literal_range_max_dist_no_emission_2) {
  INIT_V8();
  LdrLiteralRangeHelper(
      MacroAssembler::GetApproxMaxDistToConstPoolForTesting() -
          MacroAssembler::GetCheckConstPoolIntervalForTesting(),
      NoEmitExpected, EmitAtAligned);
}

#endif

TEST(add_sub_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0x0);
  __ Mov(x1, 0x1111);
  __ Mov(x2, 0xFFFFFFFFFFFFFFFFL);
  __ Mov(x3, 0x8000000000000000L);

  __ Add(x10, x0, Operand(0x123));
  __ Add(x11, x1, Operand(0x122000));
  __ Add(x12, x0, Operand(0xABC << 12));
  __ Add(x13, x2, Operand(1));

  __ Add(w14, w0, Operand(0x123));
  __ Add(w15, w1, Operand(0x122000));
  __ Add(w16, w0, Operand(0xABC << 12));
  __ Add(w17, w2, Operand(1));

  __ Sub(x20, x0, Operand(0x1));
  __ Sub(x21, x1, Operand(0x111));
  __ Sub(x22, x1, Operand(0x1 << 12));
  __ Sub(x23, x3, Operand(1));

  __ Sub(w24, w0, Operand(0x1));
  __ Sub(w25, w1, Operand(0x111));
  __ Sub(w26, w1, Operand(0x1 << 12));
  __ Sub(w27, w3, Operand(1));
  END();

  RUN();

  CHECK_EQUAL_64(0x123, x10);
  CHECK_EQUAL_64(0x123111, x11);
  CHECK_EQUAL_64(0xABC000, x12);
  CHECK_EQUAL_64(0x0, x13);

  CHECK_EQUAL_32(0x123, w14);
  CHECK_EQUAL_32(0x123111, w15);
  CHECK_EQUAL_32(0xABC000, w16);
  CHECK_EQUAL_32(0x0, w17);

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFL, x20);
  CHECK_EQUAL_64(0x1000, x21);
  CHECK_EQUAL_64(0x111, x22);
  CHECK_EQUAL_64(0x7FFFFFFFFFFFFFFFL, x23);

  CHECK_EQUAL_32(0xFFFFFFFF, w24);
  CHECK_EQUAL_32(0x1000, w25);
  CHECK_EQUAL_32(0x111, w26);
  CHECK_EQUAL_32(0xFFFFFFFF, w27);
}

TEST(add_sub_wide_imm) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0x0);
  __ Mov(x1, 0x1);

  __ Add(x10, x0, Operand(0x1234567890ABCDEFUL));
  __ Add(x11, x1, Operand(0xFFFFFFFF));

  __ Add(w12, w0, Operand(0x12345678));
  __ Add(w13, w1, Operand(0xFFFFFFFF));

  __ Add(w28, w0, Operand(kWMinInt));
  __ Sub(w19, w0, Operand(kWMinInt));

  __ Sub(x20, x0, Operand(0x1234567890ABCDEFUL));
  __ Sub(w21, w0, Operand(0x12345678));
  END();

  RUN();

  CHECK_EQUAL_64(0x1234567890ABCDEFUL, x10);
  CHECK_EQUAL_64(0x100000000UL, x11);

  CHECK_EQUAL_32(0x12345678, w12);
  CHECK_EQUAL_64(0x0, x13);

  CHECK_EQUAL_32(kWMinInt, w28);
  CHECK_EQUAL_32(kWMinInt, w19);

  CHECK_EQUAL_64(-0x1234567890ABCDEFLL, x20);
  CHECK_EQUAL_32(-0x12345678, w21);
}

TEST(add_sub_shifted) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);
  __ Mov(x3, 0xFFFFFFFFFFFFFFFFL);

  __ Add(x10, x1, Operand(x2));
  __ Add(x11, x0, Operand(x1, LSL, 8));
  __ Add(x12, x0, Operand(x1, LSR, 8));
  __ Add(x13, x0, Operand(x1, ASR, 8));
  __ Add(x14, x0, Operand(x2, ASR, 8));
  __ Add(w15, w0, Operand(w1, ASR, 8));
  __ Add(w28, w3, Operand(w1, ROR, 8));
  __ Add(x19, x3, Operand(x1, ROR, 8));

  __ Sub(x20, x3, Operand(x2));
  __ Sub(x21, x3, Operand(x1, LSL, 8));
  __ Sub(x22, x3, Operand(x1, LSR, 8));
  __ Sub(x23, x3, Operand(x1, ASR, 8));
  __ Sub(x24, x3, Operand(x2, ASR, 8));
  __ Sub(w25, w3, Operand(w1, ASR, 8));
  __ Sub(w26, w3, Operand(w1, ROR, 8));
  __ Sub(x27, x3, Operand(x1, ROR, 8));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFFFL, x10);
  CHECK_EQUAL_64(0x23456789ABCDEF00L, x11);
  CHECK_EQUAL_64(0x000123456789ABCDL, x12);
  CHECK_EQUAL_64(0x000123456789ABCDL, x13);
  CHECK_EQUAL_64(0xFFFEDCBA98765432L, x14);
  CHECK_EQUAL_64(0xFF89ABCD, x15);
  CHECK_EQUAL_64(0xEF89ABCC, x28);
  CHECK_EQUAL_64(0xEF0123456789ABCCL, x19);

  CHECK_EQUAL_64(0x0123456789ABCDEFL, x20);
  CHECK_EQUAL_64(0xDCBA9876543210FFL, x21);
  CHECK_EQUAL_64(0xFFFEDCBA98765432L, x22);
  CHECK_EQUAL_64(0xFFFEDCBA98765432L, x23);
  CHECK_EQUAL_64(0x000123456789ABCDL, x24);
  CHECK_EQUAL_64(0x00765432, x25);
  CHECK_EQUAL_64(0x10765432, x26);
  CHECK_EQUAL_64(0x10FEDCBA98765432L, x27);
}

TEST(add_sub_extended) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0x0123456789ABCDEFL);
  __ Mov(x2, 0xFEDCBA9876543210L);
  __ Mov(w3, 0x80);

  __ Add(x10, x0, Operand(x1, UXTB, 0));
  __ Add(x11, x0, Operand(x1, UXTB, 1));
  __ Add(x12, x0, Operand(x1, UXTH, 2));
  __ Add(x13, x0, Operand(x1, UXTW, 4));

  __ Add(x14, x0, Operand(x1, SXTB, 0));
  __ Add(x15, x0, Operand(x1, SXTB, 1));
  __ Add(x16, x0, Operand(x1, SXTH, 2));
  __ Add(x17, x0, Operand(x1, SXTW, 3));
  __ Add(x4, x0, Operand(x2, SXTB, 0));
  __ Add(x19, x0, Operand(x2, SXTB, 1));
  __ Add(x20, x0, Operand(x2, SXTH, 2));
  __ Add(x21, x0, Operand(x2, SXTW, 3));

  __ Add(x22, x1, Operand(x2, SXTB, 1));
  __ Sub(x23, x1, Operand(x2, SXTB, 1));

  __ Add(w24, w1, Operand(w2, UXTB, 2));
  __ Add(w25, w0, Operand(w1, SXTB, 0));
  __ Add(w26, w0, Operand(w1, SXTB, 1));
  __ Add(w27, w2, Operand(w1, SXTW, 3));

  __ Add(w28, w0, Operand(w1, SXTW, 3));
  __ Add(x29, x0, Operand(w1, SXTW, 3));

  __ Sub(x30, x0, Operand(w3, SXTB, 1));
  END();

  RUN();

  CHECK_EQUAL_64(0xEFL, x10);
  CHECK_EQUAL_64(0x1DEL, x11);
  CHECK_EQUAL_64(0x337BCL, x12);
  CHECK_EQUAL_64(0x89ABCDEF0L, x13);

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFEFL, x14);
  CHECK_EQUAL_64(0xFFFFFFFFFFFFFFDEL, x15);
  CHECK_EQUAL_64(0xFFFFFFFFFFFF37BCL, x16);
  CHECK_EQUAL_64(0xFFFFFFFC4D5E6F78L, x17);
  CHECK_EQUAL_64(0x10L, x4);
  CHECK_EQUAL_64(0x20L, x19);
  CHECK_EQUAL_64(0xC840L, x20);
  CHECK_EQUAL_64(0x3B2A19080L, x21);

  CHECK_EQUAL_64(0x0123456789ABCE0FL, x22);
  CHECK_EQUAL_64(0x0123456789ABCDCFL, x23);

  CHECK_EQUAL_32(0x89ABCE2F, w24);
  CHECK_EQUAL_32(0xFFFFFFEF, w25);
  CHECK_EQUAL_32(0xFFFFFFDE, w26);
  CHECK_EQUAL_32(0xC3B2A188, w27);

  CHECK_EQUAL_32(0x4D5E6F78, w28);
  CHECK_EQUAL_64(0xFFFFFFFC4D5E6F78L, x29);

  CHECK_EQUAL_64(256, x30);
}

TEST(add_sub_negative) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 4687);
  __ Mov(x2, 0x1122334455667788);
  __ Mov(w3, 0x11223344);
  __ Mov(w4, 400000);

  __ Add(x10, x0, -42);
  __ Add(x11, x1, -687);
  __ Add(x12, x2, -0x88);

  __ Sub(x13, x0, -600);
  __ Sub(x14, x1, -313);
  __ Sub(x15, x2, -0x555);

  __ Add(w19, w3, -0x344);
  __ Add(w20, w4, -2000);

  __ Sub(w21, w3, -0xBC);
  __ Sub(w22, w4, -2000);
  END();

  RUN();

  CHECK_EQUAL_64(-42, x10);
  CHECK_EQUAL_64(4000, x11);
  CHECK_EQUAL_64(0x1122334455667700, x12);

  CHECK_EQUAL_64(600, x13);
  CHECK_EQUAL_64(5000, x14);
  CHECK_EQUAL_64(0x1122334455667CDD, x15);

  CHECK_EQUAL_32(0x11223000, w19);
  CHECK_EQUAL_32(398000, w20);

  CHECK_EQUAL_32(0x11223400, w21);
  CHECK_EQUAL_32(402000, w22);
}

TEST(add_sub_zero) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0);
  __ Mov(x1, 0);
  __ Mov(x2, 0);

  Label blob1;
  __ Bind(&blob1);
  __ Add(x0, x0, 0);
  __ Sub(x1, x1, 0);
  __ Sub(x2, x2, xzr);
  CHECK_EQ(0u, __ SizeOfCodeGeneratedSince(&blob1));

  Label blob2;
  __ Bind(&blob2);
  __ Add(w3, w3, 0);
  CHECK_NE(0u, __ SizeOfCodeGeneratedSince(&blob2));

  Label blob3;
  __ Bind(&blob3);
  __ Sub(w3, w3, wzr);
  CHECK_NE(0u, __ SizeOfCodeGeneratedSince(&blob3));

  END();

  RUN();

  CHECK_EQUAL_64(0, x0);
  CHECK_EQUAL_64(0, x1);
  CHECK_EQUAL_64(0, x2);
}

TEST(preshift_immediates) {
  INIT_V8();
  SETUP();

  START();
  // Test operations involving immediates that could be generated using a
  // pre-shifted encodable immediate followed by a post-shift applied to
  // the arithmetic or logical operation.

  // Save sp.
  __ Mov(x29, sp);

  // Set the registers to known values.
  __ Mov(x0, 0x1000);
  __ Mov(sp, 0x1000);

  // Arithmetic ops.
  __ Add(x1, x0, 0x1F7DE);
  __ Add(w2, w0, 0xFFFFFF1);
  __ Adds(x3, x0, 0x18001);
  __ Adds(w4, w0, 0xFFFFFF1);
  __ Add(x5, x0, 0x10100);
  __ Sub(w6, w0, 0xFFFFFF1);
  __ Subs(x7, x0, 0x18001);
  __ Subs(w8, w0, 0xFFFFFF1);

  // Logical ops.
  __ And(x9, x0, 0x1F7DE);
  __ Orr(w10, w0, 0xFFFFFF1);
  __ Eor(x11, x0, 0x18001);

  // Ops using the stack pointer.
  __ Add(sp, sp, 0x1F7F0);
  __ Mov(x12, sp);
  __ Mov(sp, 0x1000);

  __ Adds(x13, sp, 0x1F7F0);

  __ Orr(sp, x0, 0x1F7F0);
  __ Mov(x14, sp);
  __ Mov(sp, 0x1000);

  __ Add(sp, sp, 0x10100);
  __ Mov(x15, sp);

  //  Restore sp.
  __ Mov(sp, x29);
  END();

  RUN();

  CHECK_EQUAL_64(0x1000, x0);
  CHECK_EQUAL_64(0x207DE, x1);
  CHECK_EQUAL_64(0x10000FF1, x2);
  CHECK_EQUAL_64(0x19001, x3);
  CHECK_EQUAL_64(0x10000FF1, x4);
  CHECK_EQUAL_64(0x11100, x5);
  CHECK_EQUAL_64(0xF000100F, x6);
  CHECK_EQUAL_64(0xFFFFFFFFFFFE8FFF, x7);
  CHECK_EQUAL_64(0xF000100F, x8);
  CHECK_EQUAL_64(0x1000, x9);
  CHECK_EQUAL_64(0xFFFFFF1, x10);
  CHECK_EQUAL_64(0x207F0, x12);
  CHECK_EQUAL_64(0x207F0, x13);
  CHECK_EQUAL_64(0x1F7F0, x14);
  CHECK_EQUAL_64(0x11100, x15);
}

TEST(claim_drop_zero) {
  INIT_V8();
  SETUP();

  START();

  Label start;
  __ Bind(&start);
  __ Claim(0);
  __ Drop(0);
  __ Claim(xzr, 8);
  __ Drop(xzr, 8);
  __ Claim(xzr, 0);
  __ Drop(xzr, 0);
  __ Claim(x7, 0);
  __ Drop(x7, 0);
  CHECK_EQ(0u, __ SizeOfCodeGeneratedSince(&start));

  END();

  RUN();
}

TEST(neg) {
  INIT_V8();
  SETUP();

  START();
  __ Mov(x0, 0xF123456789ABCDEFL);

  // Immediate.
  __ Neg(x1, 0x123);
  __ Neg(w2, 0x123);

  // Shifted.
  __ Neg(x3, Operand(x0, LSL, 1));
  __ Neg(w4, Operand(w0, LSL, 2));
  __ Neg(x5, Operand(x0, LSR, 3));
  __ Neg(w6, Operand(w0, LSR, 4));
  __ Neg(x7, Operand(x0, ASR, 5));
  __ Neg(w8, Operand(w0, ASR, 6));

  // Extended.
  __ Neg(w9, Operand(w0, UXTB));
  __ Neg(x10, Operand(x0, SXTB, 1));
  __ Neg(w11, Operand(w0, UXTH, 2));
  __ Neg(x12, Operand(x0, SXTH, 3));
  __ Neg(w13, Operand(w0, UXTW, 4));
  __ Neg(x14, Operand(x0, SXTW, 4));
  END();

  RUN();

  CHECK_EQUAL_64(0xFFFFFFFFFFFFFEDDUL, x1);
  CHECK_EQUAL_64(0xFFFFFEDD, x2);
  CHECK_EQUAL_64(0x1DB97530ECA86422UL, x3);
  CHECK_EQUAL_64(0xD950C844, x4);
  CHECK_EQUAL_64(0xE1DB97530ECA8643UL, x5);
  CHECK_EQUAL_64(0xF7654322, x6);
  CHECK_EQUAL_64(0x0076E5D4C3B2A191UL, x7);
  CHECK_EQUAL_64(0x01D950C9, x8);
  CHECK_EQUAL_64(0xFFFFFF11, x9);
  CHECK_EQUAL_64(0x0000000000000022UL, x10);
  CHECK_EQUAL_64(0xFFFCC844, x11);
  CHECK_EQUAL_64(0x0000000000019088UL, x12);
  CHECK_EQUAL_64(0x65432110, x13);
  CHECK_EQUAL_64(0x0000000765432110UL, x14);
}

template <typename T, typename Op>
static void AdcsSbcsHelper(Op op, T left, T right, int carry, T expected,
                           StatusFlags expected_flags) {
  int reg_size = sizeof(T) * 8;
  auto left_reg = Register::Create(0, reg_size);
  auto right_reg = Register::Create(1, reg_size);
  auto result_reg = Register::Create(2, reg_size);

  SETUP();
  START();

  __ Mov(left_reg, left);
  __ Mov(right_reg, right);
  __ Mov(x10, (carry ? CFlag : NoFlag));

  __ Msr(NZCV, x10);
  (masm.*op)(result_reg, left_reg, right_reg);

  END();
  RUN();

  CHECK_EQUAL_64(left, left_reg.X());
  CHECK_EQUAL_64(right, right_reg.X());
  CHECK_EQUAL_64(expected, result_reg.X());
  CHECK_EQUAL_NZCV(expected_flags);
}

TEST(adcs_sbcs_x) {
  INIT_V8();
  uint64_t inputs[] = {
      0x0000000000000000, 0x0000000000000001, 0x7FFFFFFFFFFFFFFE,
      0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0x8000000000000001,
      0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF,
  };
  static const size_t input_count = sizeof(inputs) / sizeof(inputs[0]);

  struct Expected {
    uint64_t carry0_result;
    StatusFlags carry0_flags;
    uint64_t carry1_result;
    StatusFlags carry1_flags;
  };

  static const Expected expected_adcs_x[input_count][input_count] = {
      {{0x0000000000000000, ZFlag, 0x0000000000000001, NoFlag},
       {0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag},
       {0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x8000000000000000, NFlag, 0x8000000000000001, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag}},
      {{0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag},
       {0x0000000000000002, NoFlag, 0x0000000000000003, NoFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag}},
      {{0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0xFFFFFFFFFFFFFFFC, NVFlag, 0xFFFFFFFFFFFFFFFD, NVFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag}},
      {{0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0xFFFFFFFFFFFFFFFE, NVFlag, 0xFFFFFFFFFFFFFFFF, NVFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag}},
      {{0x8000000000000000, NFlag, 0x8000000000000001, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCVFlag, 0x0000000000000001, CVFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag}},
      {{0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x0000000000000002, CVFlag, 0x0000000000000003, CVFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag}},
      {{0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0xFFFFFFFFFFFFFFFC, NCFlag, 0xFFFFFFFFFFFFFFFD, NCFlag},
       {0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag}},
      {{0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag},
       {0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag},
       {0xFFFFFFFFFFFFFFFE, NCFlag, 0xFFFFFFFFFFFFFFFF, NCFlag}}};

  static const Expected expected_sbcs_x[input_count][input_count] = {
      {{0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000000, NFlag, 0x8000000000000001, NFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag},
       {0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag},
       {0x0000000000000000, ZFlag, 0x0000000000000001, NoFlag}},
      {{0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x0000000000000002, NoFlag, 0x0000000000000003, NoFlag},
       {0x0000000000000001, NoFlag, 0x0000000000000002, NoFlag}},
      {{0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0xFFFFFFFFFFFFFFFC, NVFlag, 0xFFFFFFFFFFFFFFFD, NVFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag},
       {0x7FFFFFFFFFFFFFFE, NoFlag, 0x7FFFFFFFFFFFFFFF, NoFlag}},
      {{0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NVFlag, 0xFFFFFFFFFFFFFFFF, NVFlag},
       {0xFFFFFFFFFFFFFFFD, NVFlag, 0xFFFFFFFFFFFFFFFE, NVFlag},
       {0x8000000000000000, NVFlag, 0x8000000000000001, NVFlag},
       {0x7FFFFFFFFFFFFFFF, NoFlag, 0x8000000000000000, NVFlag}},
      {{0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x0000000000000000, ZCVFlag, 0x0000000000000001, CVFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag},
       {0x8000000000000000, NFlag, 0x8000000000000001, NFlag}},
      {{0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x0000000000000002, CVFlag, 0x0000000000000003, CVFlag},
       {0x0000000000000001, CVFlag, 0x0000000000000002, CVFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0x8000000000000002, NFlag, 0x8000000000000003, NFlag},
       {0x8000000000000001, NFlag, 0x8000000000000002, NFlag}},
      {{0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag},
       {0xFFFFFFFFFFFFFFFC, NCFlag, 0xFFFFFFFFFFFFFFFD, NCFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x7FFFFFFFFFFFFFFE, CVFlag, 0x7FFFFFFFFFFFFFFF, CVFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x7FFFFFFFFFFFFFFC, CFlag, 0x7FFFFFFFFFFFFFFD, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag},
       {0xFFFFFFFFFFFFFFFE, NFlag, 0xFFFFFFFFFFFFFFFF, NFlag}},
      {{0xFFFFFFFFFFFFFFFE, NCFlag, 0xFFFFFFFFFFFFFFFF, NCFlag},
       {0xFFFFFFFFFFFFFFFD, NCFlag, 0xFFFFFFFFFFFFFFFE, NCFlag},
       {0x8000000000000000, NCFlag, 0x8000000000000001, NCFlag},
       {0x7FFFFFFFFFFFFFFF, CVFlag, 0x8000000000000000, NCFlag},
       {0x7FFFFFFFFFFFFFFE, CFlag, 0x7FFFFFFFFFFFFFFF, CFlag},
       {0x7FFFFFFFFFFFFFFD, CFlag, 0x7FFFFFFFFFFFFFFE, CFlag},
       {0x0000000000000000, ZCFlag, 0x0000000000000001, CFlag},
       {0xFFFFFFFFFFFFFFFF, NFlag, 0x0000000000000000, ZCFlag}}};

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_adcs_x[left][right];
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Adcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }

  for (size_t left = 0; left < input_count; left++) {
    for (size_t right = 0; right < input_count; right++) {
      const Expected& expected = expected_sbcs_x[left][right];
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 0,
                     expected.carry0_result, expected.carry0_flags);
      AdcsSbcsHelper(&MacroAssembler::Sbcs, inputs[left], inputs[right], 1,
                     expected.carry1_result, expected.carry1_flags);
    }
  }
}

TEST(adcs_sbcs_w) {
  INIT_V8();
  uint32_t inputs[] = {
      0x00000000, 0x00000001, 0x7FFFFFFE, 0x7FFFFFFF,
      0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF,
  };
  static const size_t input_count = sizeof(inputs) / sizeof(inputs[0]);

  struct Expected {
    uint32_t carry0_result;
    StatusFlags carry0_flags;
    uint32_t carry1_result;
    StatusFlags carry1_flags;
  };

  static const Expected expected_adcs_w[input_count][input_count] = {
      {{0x00000000,
"""


```