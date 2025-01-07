Response:
The user wants a summary of the functionalities provided by the C++ header file `v8/src/codegen/ppc/macro-assembler-ppc.h`. The request also includes checks for specific file extensions and relationships to JavaScript. Finally, it's the second part of a three-part request, implying the need for a concise summary.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename suggests it's a macro assembler for the PowerPC architecture within V8's code generation. This immediately points to low-level operations related to manipulating registers, memory, and controlling program flow.

2. **Scan for key functionality categories:**  Read through the provided code, looking for groups of related functions and descriptive comments. Keywords like "Smi," "Bit testing," "Overflow handling," "Sandbox," "Pointer compression," "SIMD" stand out.

3. **Group similar functions:**  Organize the identified functionalities into logical categories. This makes the summary clearer and easier to understand. For example, functions like `SmiToInt32`, `SmiTag`, `AssertSmi`, `AssertNotSmi` clearly belong to a "Smi manipulation" category.

4. **Summarize each category:**  For each category, provide a brief explanation of its purpose. Use clear and concise language, avoiding overly technical jargon where possible. Focus on the "what" rather than the "how."

5. **Address specific instructions:**
    * **File extension check:** The prompt explicitly asks about the `.tq` extension. Since the provided content is a `.h` file, the answer is straightforward.
    * **JavaScript relationship:**  Consider how the low-level operations relate to higher-level JavaScript concepts. Smi manipulation is directly related to how V8 handles small integers. Memory operations are fundamental to object manipulation. Function calls and jumps are essential for program execution. SIMD instructions are relevant to optimized array operations.
    * **JavaScript examples:** Provide simple, illustrative JavaScript examples to demonstrate the connection between the low-level functions and their corresponding JavaScript behavior.
    * **Code logic and examples:** For functions with clear logic, like `SmiToInt32` and `SmiTag`, provide hypothetical input and output to illustrate their behavior.
    * **Common programming errors:** Think about typical mistakes developers might make related to the functionalities described. For instance, mishandling SMIs or integer overflows are common issues.

6. **Handle the "Part 2" instruction:** Since this is part 2 of 3, the summary should be concise and focus on the key functionalities without going into excessive detail.

7. **Review and refine:** Read through the generated summary to ensure accuracy, clarity, and conciseness. Check for any redundant information or areas that could be explained more effectively. Make sure all parts of the prompt are addressed.

**Self-Correction Example during the process:**

Initially, I might have just listed all the function names. However, realizing the user wants a functional overview, I would correct this by grouping the functions into categories and explaining the purpose of each category. Similarly, I might initially forget to include the JavaScript examples and then realize their importance for illustrating the high-level connection. The "Part 2" instruction is a reminder to keep the summary relatively brief.
这是 `v8/src/codegen/ppc/macro-assembler-ppc.h` 文件的第二部分，延续了第一部分的功能定义，主要提供了一系列用于在 PowerPC 架构上生成机器码的汇编指令级别的抽象和辅助方法。

**归纳一下这部分的功能：**

这部分 `macro-assembler-ppc.h` 文件的功能主要集中在以下几个方面：

1. **Smi (Small Integer) 的处理:**
   - 提供了将 Smi 类型的值转换为 Int32 和反向转换的方法 (`SmiToInt32`, `SmiTag`)。
   - 提供了断言一个寄存器是否包含 Smi 的方法 (`AssertSmi`, `AssertNotSmi`)，这些通常在调试代码中使用。

2. **位操作:**
   - 提供了从寄存器中提取特定位范围或单个位的方法 (`ExtractBitRange`, `ExtractBit`, `ExtractBitMask`)。
   - 提供了测试寄存器中特定位或位范围的方法 (`TestBit`, `TestBitMask`, `TestBitRange`)。
   - 提供了检查一个值是否为 Smi 并根据结果跳转的方法 (`TestIfSmi`, `JumpIfSmi`)。

3. **内存加载和存储:**
   - 提供了加载 Map 对象 (`LoadMap`, `LoadCompressedMap`) 和 Feedback Vector (`LoadFeedbackVector`) 的方法。
   - 提供了加载和存储不同大小整数（字节、半字、字）的方法，包括带符号和无符号扩展 (`ZeroExtByte`, `ZeroExtHalfWord`, `ZeroExtWord32`, `LoadU64`, `LoadS32` 等)。
   - 提供了加载和存储浮点数的方法 (`LoadF64`, `StoreF32` 等)。
   - 提供了加载和存储指令的原子操作版本（带有 Update 后缀）。
   - 提供了处理不同字节序（LE - Little Endian）的加载和存储方法 (`LoadU32LE`, `StoreF64LE` 等)。

4. **类型检查和转换:**
   - 提供了测试一个寄存器中的值是否可以安全转换为 Int32 的方法 (`TestIfInt32`)。
   - 提供了将双精度浮点数截断为整数的方法 (`TryInlineTruncateDoubleToI`, `TruncateDoubleToI`)，这在 JavaScript 的位操作中很常见。

5. **函数调用和跳转:**
   - 提供了调用和跳转到 JS 函数的方法 (`CallJSFunction`, `JumpJSFunction`)。
   - 提供了存储返回地址并调用的方法 (`StoreReturnAddressAndCall`)。

6. **控制流完整性 (CFI):**
   - 提供了定义函数入口点和异常处理器的占位方法 (`CodeEntry`, `ExceptionHandler`, `BindExceptionHandler`)，但注释指出当前架构不支持 CFI。

7. **V8 Sandbox 支持:**
   - 提供了一系列用于处理沙箱指针的方法，包括编码、解码、加载和存储沙箱指针字段 (`DecodeSandboxedPointer`, `LoadSandboxedPointerField`, `StoreSandboxedPointerField`)。
   - 提供了加载和存储外部指针和受信任指针字段的方法 (`LoadExternalPointerField`, `LoadTrustedPointerField`, `StoreTrustedPointerField`)，这些指针在沙箱环境中需要特殊处理。
   - 提供了加载代码指针和间接指针字段的方法 (`LoadCodePointerField`, `StoreCodePointerField`, `LoadIndirectPointerField`, `StoreIndirectPointerField`)，以及解析这些指针句柄的方法 (`ResolveIndirectPointerHandle`, `ResolveCodePointerHandle`)。

8. **指针压缩支持:**
   - 提供了将 Smi 转换为指针数组偏移量的方法 (`SmiToPtrArrayOffset`)。
   - 提供了加载和存储压缩的 Tagged 值的方法 (`LoadTaggedField`, `StoreTaggedField`)，以及解压缩 Tagged 值的方法 (`DecompressTaggedSigned`, `DecompressTagged`)。

9. **SIMD (Single Instruction, Multiple Data) 支持:**
   - 提供了大量的 SIMD 指令的抽象，用于执行向量化的操作，包括算术运算、比较运算、位运算、移位操作、类型转换、车道 (lane) 操作（提取、替换、加载、存储）等等。这些指令覆盖了 `F64x2`, `F32x4`, `I64x2`, `I32x4`, `I16x8`, `I8x16` 等不同的 SIMD 数据类型。

**关于您提出的问题：**

* **如果 `v8/src/codegen/ppc/macro-assembler-ppc.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**
   - 您是对的。以 `.tq` 结尾的文件是 V8 的 Torque 源代码。但这个文件是 `.h` 结尾的 C++ 头文件。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明。**
   - **Smi 处理:** JavaScript 中的小整数（通常在一定范围内）在 V8 内部会以 Smi 的形式表示。`SmiToInt32` 和 `SmiTag` 等方法用于在底层操作这些 Smi 值。
     ```javascript
     // 假设 V8 内部用 Smi 表示小整数
     let smallNumber = 5; // 在 V8 内部可能被表示为 Smi
     // ... V8 内部的某个操作可能需要将 smallNumber 从 Smi 转换为 Int32
     ```
   - **位操作:** JavaScript 的位运算符（如 `|`, `&`, `^`, `<<`, `>>`, `>>>`）在底层会使用这些位操作指令。
     ```javascript
     let a = 10; // 二进制 1010
     let b = 3;  // 二进制 0011
     let result = a & b; // 位与运算，结果为 2 (二进制 0010)
     // 底层可能会使用 TestBitMask, ExtractBitRange 等指令来实现
     ```
   - **类型检查和转换:** JavaScript 的类型判断和转换在底层会用到类似的方法。
     ```javascript
     function add(a, b) {
       if (typeof a === 'number' && typeof b === 'number') {
         return a + b;
       } else {
         throw new Error('Arguments must be numbers');
       }
     }
     // V8 内部在执行类型检查时，可能会用到类似 TestIfInt32 的方法来判断是否可以进行快速的整数运算。
     ```
   - **SIMD:** JavaScript 的 SIMD API (如 `Float32x4`, `Int32x4`) 的操作会直接映射到这些 SIMD 指令。
     ```javascript
     let a = Float32x4(1, 2, 3, 4);
     let b = Float32x4(5, 6, 7, 8);
     let result = a.add(b); // 底层会使用 F32x4Add 指令
     console.log(result); // 输出 Float32x4(6, 8, 10, 12)
     ```

* **如果有代码逻辑推理，请给出假设输入与输出。**
   - **`SmiToInt32(Register smi)`:**
     - 假设输入寄存器 `smi` 包含 Smi 值 `0xa` (十进制 10，Smi 编码通常左移一位，所以原始整数是 5)。
     - 输出：寄存器 `smi` 的值变为 `0x5` (十进制 5)。
   - **`SmiTag(Register reg)`:**
     - 假设输入寄存器 `reg` 包含整数值 `0x5` (十进制 5)。
     - 输出：寄存器 `reg` 的值变为 `0xa` (十进制 10，Smi 编码)。
   - **`ExtractBitRange(Register dst, Register src, int rangeStart, int rangeEnd)`:**
     - 假设输入寄存器 `src` 包含值 `0b10110100`，`rangeStart` 为 5，`rangeEnd` 为 2。
     - 输出：寄存器 `dst` 包含值 `0b00001101` (提取了从右边第 2 位到第 5 位的比特)。

* **如果涉及用户常见的编程错误，请举例说明。**
   - **Smi 溢出:** 用户在 JavaScript 中进行大量整数运算，如果超出了 Smi 的表示范围，V8 需要将其转换为 HeapObject (例如，BigInt 或 Number)。如果在底层代码中错误地假设所有小整数都是 Smi，可能会导致类型错误或性能问题。
   - **位运算的符号问题:**  JavaScript 的位运算符在处理负数时需要特别注意符号扩展。如果底层代码的位操作与 JavaScript 的语义不符，可能会导致意外的结果。例如，无符号右移 `>>>` 和有符号右移 `>>` 的区别。
   - **SIMD 数据类型不匹配:** 在使用 SIMD API 时，如果操作的数据类型不匹配（例如，尝试将 `Float32x4` 和 `Int32x4` 直接相加），会导致错误。

总而言之，这部分 `macro-assembler-ppc.h` 文件是 V8 在 PowerPC 架构上生成高效机器码的关键组成部分，它提供了对底层硬件操作的抽象，使得 V8 能够执行 JavaScript 代码。

Prompt: 
```
这是目录为v8/src/codegen/ppc/macro-assembler-ppc.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/ppc/macro-assembler-ppc.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
dst, src, Operand(kSmiShift), rc);
    }
  }
  void SmiToInt32(Register smi) {
    if (v8_flags.enable_slow_asserts) {
      AssertSmi(smi);
    }
    DCHECK(SmiValuesAre32Bits() || SmiValuesAre31Bits());
    SmiUntag(smi);
  }

  // Shift left by kSmiShift
  void SmiTag(Register reg, RCBit rc = LeaveRC) { SmiTag(reg, reg, rc); }
  void SmiTag(Register dst, Register src, RCBit rc = LeaveRC) {
    ShiftLeftU64(dst, src, Operand(kSmiShift), rc);
  }

  // Abort execution if argument is a smi, enabled via --debug-code.
  void AssertNotSmi(Register object) NOOP_UNLESS_DEBUG_CODE;
  void AssertSmi(Register object) NOOP_UNLESS_DEBUG_CODE;

  void ZeroExtByte(Register dst, Register src);
  void ZeroExtHalfWord(Register dst, Register src);
  void ZeroExtWord32(Register dst, Register src);

  // ---------------------------------------------------------------------------
  // Bit testing/extraction
  //
  // Bit numbering is such that the least significant bit is bit 0
  // (for consistency between 32/64-bit).

  // Extract consecutive bits (defined by rangeStart - rangeEnd) from src
  // and, if !test, shift them into the least significant bits of dst.
  inline void ExtractBitRange(Register dst, Register src, int rangeStart,
                              int rangeEnd, RCBit rc = LeaveRC,
                              bool test = false) {
    DCHECK(rangeStart >= rangeEnd && rangeStart < kBitsPerSystemPointer);
    int rotate = (rangeEnd == 0) ? 0 : kBitsPerSystemPointer - rangeEnd;
    int width = rangeStart - rangeEnd + 1;
    if (rc == SetRC && rangeStart < 16 && (rangeEnd == 0 || test)) {
      // Prefer faster andi when applicable.
      andi(dst, src, Operand(((1 << width) - 1) << rangeEnd));
    } else {
      rldicl(dst, src, rotate, kBitsPerSystemPointer - width, rc);
    }
  }

  inline void ExtractBit(Register dst, Register src, uint32_t bitNumber,
                         RCBit rc = LeaveRC, bool test = false) {
    ExtractBitRange(dst, src, bitNumber, bitNumber, rc, test);
  }

  // Extract consecutive bits (defined by mask) from src and place them
  // into the least significant bits of dst.
  inline void ExtractBitMask(Register dst, Register src, uintptr_t mask,
                             RCBit rc = LeaveRC, bool test = false) {
    int start = kBitsPerSystemPointer - 1;
    int end;
    uintptr_t bit = (1L << start);

    while (bit && (mask & bit) == 0) {
      start--;
      bit >>= 1;
    }
    end = start;
    bit >>= 1;

    while (bit && (mask & bit)) {
      end--;
      bit >>= 1;
    }

    // 1-bits in mask must be contiguous
    DCHECK(bit == 0 || (mask & ((bit << 1) - 1)) == 0);

    ExtractBitRange(dst, src, start, end, rc, test);
  }

  // Test single bit in value.
  inline void TestBit(Register value, int bitNumber, Register scratch = r0) {
    ExtractBitRange(scratch, value, bitNumber, bitNumber, SetRC, true);
  }

  // Test consecutive bit range in value.  Range is defined by mask.
  inline void TestBitMask(Register value, uintptr_t mask,
                          Register scratch = r0) {
    ExtractBitMask(scratch, value, mask, SetRC, true);
  }
  // Test consecutive bit range in value.  Range is defined by
  // rangeStart - rangeEnd.
  inline void TestBitRange(Register value, int rangeStart, int rangeEnd,
                           Register scratch = r0) {
    ExtractBitRange(scratch, value, rangeStart, rangeEnd, SetRC, true);
  }

  inline void TestIfSmi(Register value, Register scratch) {
    TestBitRange(value, kSmiTagSize - 1, 0, scratch);
  }
  // Jump the register contains a smi.
  inline void JumpIfSmi(Register value, Label* smi_label) {
    TestIfSmi(value, r0);
    beq(smi_label, cr0);  // branch if SMI
  }
  void JumpIfEqual(Register x, int32_t y, Label* dest);
  void JumpIfLessThan(Register x, int32_t y, Label* dest);

  void LoadMap(Register destination, Register object);
  void LoadCompressedMap(Register dst, Register object, Register scratch);

  void LoadFeedbackVector(Register dst, Register closure, Register scratch,
                          Label* fbv_undef);

  inline void TestIfInt32(Register value, Register scratch,
                          CRegister cr = cr7) {
    // High bits must be identical to fit into an 32-bit integer
    extsw(scratch, value);
    CmpS64(scratch, value, cr);
  }

  // Overflow handling functions.
  // Usage: call the appropriate arithmetic function and then call one of the
  // flow control functions with the corresponding label.

  // Compute dst = left + right, setting condition codes. dst may be same as
  // either left or right (or a unique register). left and right must not be
  // the same register.
  void AddAndCheckForOverflow(Register dst, Register left, Register right,
                              Register overflow_dst, Register scratch = r0);
  void AddAndCheckForOverflow(Register dst, Register left, intptr_t right,
                              Register overflow_dst, Register scratch = r0);

  // Compute dst = left - right, setting condition codes. dst may be same as
  // either left or right (or a unique register). left and right must not be
  // the same register.
  void SubAndCheckForOverflow(Register dst, Register left, Register right,
                              Register overflow_dst, Register scratch = r0);

  // Performs a truncating conversion of a floating point number as used by
  // the JS bitwise operations. See ECMA-262 9.5: ToInt32. Goes to 'done' if it
  // succeeds, otherwise falls through if result is saturated. On return
  // 'result' either holds answer, or is clobbered on fall through.
  void TryInlineTruncateDoubleToI(Register result, DoubleRegister input,
                                  Label* done);
  void TruncateDoubleToI(Isolate* isolate, Zone* zone, Register result,
                         DoubleRegister double_input, StubCallMode stub_mode);

  void LoadConstantPoolPointerRegister();

  // Loads the constant pool pointer (kConstantPoolRegister).
  void LoadConstantPoolPointerRegisterFromCodeTargetAddress(
      Register code_target_address, Register scratch1, Register scratch2);
  void AbortConstantPoolBuilding() {
#ifdef DEBUG
    // Avoid DCHECK(!is_linked()) failure in ~Label()
    bind(ConstantPoolPosition());
#endif
  }

  // Convenience functions to call/jmp to the code of a JSFunction object.
  void CallJSFunction(Register function_object, uint16_t argument_count,
                      Register scratch);
  void JumpJSFunction(Register function_object, Register scratch,
                      JumpMode jump_mode = JumpMode::kJump);

  // Generates an instruction sequence s.t. the return address points to the
  // instruction following the call.
  // The return address on the stack is used by frame iteration.
  void StoreReturnAddressAndCall(Register target);

  // Control-flow integrity:

  // Define a function entrypoint. This doesn't emit any code for this
  // architecture, as control-flow integrity is not supported for it.
  void CodeEntry() {}
  // Define an exception handler.
  void ExceptionHandler() {}
  // Define an exception handler and bind a label.
  void BindExceptionHandler(Label* label) { bind(label); }

  // ---------------------------------------------------------------------------
  // V8 Sandbox support

  // Transform a SandboxedPointer from/to its encoded form, which is used when
  // the pointer is stored on the heap and ensures that the pointer will always
  // point into the sandbox.
  void DecodeSandboxedPointer(Register value);
  void LoadSandboxedPointerField(Register destination,
                                 const MemOperand& field_operand,
                                 Register scratch = no_reg);
  void StoreSandboxedPointerField(Register value,
                                  const MemOperand& dst_field_operand,
                                  Register scratch = no_reg);

  // Loads a field containing off-heap pointer and does necessary decoding
  // if sandboxed external pointers are enabled.
  void LoadExternalPointerField(Register destination, MemOperand field_operand,
                                ExternalPointerTag tag,
                                Register isolate_root = no_reg,
                                Register scratch = no_reg);

  // Load a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  void LoadTrustedPointerField(Register destination, MemOperand field_operand,
                               IndirectPointerTag tag,
                               Register scratch = no_reg);

  // Store a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  void StoreTrustedPointerField(Register value, MemOperand dst_field_operand,
                                Register scratch = no_reg);

  // Load a code pointer field.
  // These are special versions of trusted pointers that, when the sandbox is
  // enabled, reference code objects through the code pointer table.
  void LoadCodePointerField(Register destination, MemOperand field_operand,
                            Register scratch) {
    LoadTrustedPointerField(destination, field_operand, kCodeIndirectPointerTag,
                            scratch);
  }
  // Store a code pointer field.
  void StoreCodePointerField(Register value, MemOperand dst_field_operand,
                             Register scratch = no_reg) {
    StoreTrustedPointerField(value, dst_field_operand, scratch);
  }

  // Load an indirect pointer field.
  // Only available when the sandbox is enabled.
  void LoadIndirectPointerField(Register destination, MemOperand field_operand,
                                IndirectPointerTag tag, Register scratch);

  // Store an indirect pointer field.
  // Only available when the sandbox is enabled.
  void StoreIndirectPointerField(Register value, MemOperand dst_field_operand,
                                 Register scratch);

#ifdef V8_ENABLE_SANDBOX
  // Retrieve the heap object referenced by the given indirect pointer handle,
  // which can either be a trusted pointer handle or a code pointer handle.
  void ResolveIndirectPointerHandle(Register destination, Register handle,
                                    IndirectPointerTag tag,
                                    Register scratch = no_reg);

  // Retrieve the heap object referenced by the given trusted pointer handle.
  void ResolveTrustedPointerHandle(Register destination, Register handle,
                                   IndirectPointerTag tag,
                                   Register scratch = no_reg);

  // Retrieve the Code object referenced by the given code pointer handle.
  void ResolveCodePointerHandle(Register destination, Register handle,
                                Register scratch = no_reg);

  // Load the pointer to a Code's entrypoint via a code pointer.
  // Only available when the sandbox is enabled as it requires the code pointer
  // table.
  void LoadCodeEntrypointViaCodePointer(Register destination,
                                        MemOperand field_operand,
                                        Register scratch = no_reg);

#endif

  // ---------------------------------------------------------------------------
  // Pointer compression Support

  void SmiToPtrArrayOffset(Register dst, Register src) {
#if defined(V8_COMPRESS_POINTERS) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
    static_assert(kSmiTag == 0 && kSmiShift < kSystemPointerSizeLog2);
    ShiftLeftU64(dst, src, Operand(kSystemPointerSizeLog2 - kSmiShift));
#else
    static_assert(kSmiTag == 0 && kSmiShift > kSystemPointerSizeLog2);
    ShiftRightS64(dst, src, Operand(kSmiShift - kSystemPointerSizeLog2));
#endif
  }

  // Loads a field containing any tagged value and decompresses it if necessary.
  void LoadTaggedField(const Register& destination,
                       const MemOperand& field_operand,
                       const Register& scratch = no_reg);
  void LoadTaggedSignedField(Register destination, MemOperand field_operand,
                             Register scratch);

  // Compresses and stores tagged value to given on-heap location.
  void StoreTaggedField(const Register& value,
                        const MemOperand& dst_field_operand,
                        const Register& scratch = no_reg);

  void DecompressTaggedSigned(Register destination, MemOperand field_operand);
  void DecompressTaggedSigned(Register destination, Register src);
  void DecompressTagged(Register destination, MemOperand field_operand);
  void DecompressTagged(Register destination, Register source);
  void DecompressTagged(const Register& destination, Tagged_t immediate);

  void LoadF64(DoubleRegister dst, const MemOperand& mem,
               Register scratch = no_reg);
  void LoadF32(DoubleRegister dst, const MemOperand& mem,
               Register scratch = no_reg);

  void StoreF32(DoubleRegister src, const MemOperand& mem,
                Register scratch = no_reg);
  void StoreF64(DoubleRegister src, const MemOperand& mem,
                Register scratch = no_reg);

  void LoadF32WithUpdate(DoubleRegister dst, const MemOperand& mem,
                         Register scratch = no_reg);
  void LoadF64WithUpdate(DoubleRegister dst, const MemOperand& mem,
                         Register scratch = no_reg);

  void StoreF32WithUpdate(DoubleRegister src, const MemOperand& mem,
                          Register scratch = no_reg);
  void StoreF64WithUpdate(DoubleRegister src, const MemOperand& mem,
                          Register scratch = no_reg);

  void LoadU64(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadU32(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadS32(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadU16(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadS16(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadU8(Register dst, const MemOperand& mem, Register scratch = no_reg);
  void LoadS8(Register dst, const MemOperand& mem, Register scratch = no_reg);

  void StoreU64(Register src, const MemOperand& mem, Register scratch = no_reg);
  void StoreU32(Register src, const MemOperand& mem, Register scratch);
  void StoreU16(Register src, const MemOperand& mem, Register scratch);
  void StoreU8(Register src, const MemOperand& mem, Register scratch);

  void LoadU64WithUpdate(Register dst, const MemOperand& mem,
                         Register scratch = no_reg);
  void StoreU64WithUpdate(Register src, const MemOperand& mem,
                          Register scratch = no_reg);

  void LoadU64LE(Register dst, const MemOperand& mem, Register scratch);
  void LoadU32LE(Register dst, const MemOperand& mem, Register scratch);
  void LoadU16LE(Register dst, const MemOperand& mem, Register scratch);
  void StoreU64LE(Register src, const MemOperand& mem, Register scratch);
  void StoreU32LE(Register src, const MemOperand& mem, Register scratch);
  void StoreU16LE(Register src, const MemOperand& mem, Register scratch);

  void LoadS32LE(Register dst, const MemOperand& mem, Register scratch);
  void LoadS16LE(Register dst, const MemOperand& mem, Register scratch);

  void LoadF64LE(DoubleRegister dst, const MemOperand& mem, Register scratch,
                 Register scratch2);
  void LoadF32LE(DoubleRegister dst, const MemOperand& mem, Register scratch,
                 Register scratch2);

  void StoreF32LE(DoubleRegister src, const MemOperand& mem, Register scratch,
                  Register scratch2);
  void StoreF64LE(DoubleRegister src, const MemOperand& mem, Register scratch,
                  Register scratch2);

  // Simd Support.
#define SIMD_BINOP_LIST(V) \
  V(F64x2Add)              \
  V(F64x2Sub)              \
  V(F64x2Mul)              \
  V(F64x2Div)              \
  V(F64x2Eq)               \
  V(F64x2Lt)               \
  V(F64x2Le)               \
  V(F32x4Add)              \
  V(F32x4Sub)              \
  V(F32x4Mul)              \
  V(F32x4Div)              \
  V(F32x4Min)              \
  V(F32x4Max)              \
  V(F32x4Eq)               \
  V(F32x4Lt)               \
  V(F32x4Le)               \
  V(I64x2Add)              \
  V(I64x2Sub)              \
  V(I64x2Eq)               \
  V(I64x2GtS)              \
  V(I32x4MinS)             \
  V(I32x4MinU)             \
  V(I32x4MaxS)             \
  V(I32x4MaxU)             \
  V(I32x4Add)              \
  V(I32x4Sub)              \
  V(I32x4Mul)              \
  V(I32x4Eq)               \
  V(I32x4GtS)              \
  V(I32x4GtU)              \
  V(I32x4DotI16x8S)        \
  V(I16x8Add)              \
  V(I16x8Sub)              \
  V(I16x8Mul)              \
  V(I16x8MinS)             \
  V(I16x8MinU)             \
  V(I16x8MaxS)             \
  V(I16x8MaxU)             \
  V(I16x8Eq)               \
  V(I16x8GtS)              \
  V(I16x8GtU)              \
  V(I16x8AddSatS)          \
  V(I16x8SubSatS)          \
  V(I16x8AddSatU)          \
  V(I16x8SubSatU)          \
  V(I16x8SConvertI32x4)    \
  V(I16x8UConvertI32x4)    \
  V(I16x8RoundingAverageU) \
  V(I16x8Q15MulRSatS)      \
  V(I8x16Add)              \
  V(I8x16Sub)              \
  V(I8x16MinS)             \
  V(I8x16MinU)             \
  V(I8x16MaxS)             \
  V(I8x16MaxU)             \
  V(I8x16Eq)               \
  V(I8x16GtS)              \
  V(I8x16GtU)              \
  V(I8x16AddSatS)          \
  V(I8x16SubSatS)          \
  V(I8x16AddSatU)          \
  V(I8x16SubSatU)          \
  V(I8x16SConvertI16x8)    \
  V(I8x16UConvertI16x8)    \
  V(I8x16RoundingAverageU) \
  V(S128And)               \
  V(S128Or)                \
  V(S128Xor)               \
  V(S128AndNot)

#define PROTOTYPE_SIMD_BINOP(name) \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2);
  SIMD_BINOP_LIST(PROTOTYPE_SIMD_BINOP)
#undef PROTOTYPE_SIMD_BINOP
#undef SIMD_BINOP_LIST

#define SIMD_BINOP_WITH_SCRATCH_LIST(V) \
  V(F64x2Ne)                            \
  V(F64x2Pmin)                          \
  V(F64x2Pmax)                          \
  V(F32x4Ne)                            \
  V(F32x4Pmin)                          \
  V(F32x4Pmax)                          \
  V(I64x2Ne)                            \
  V(I64x2GeS)                           \
  V(I64x2ExtMulLowI32x4S)               \
  V(I64x2ExtMulHighI32x4S)              \
  V(I64x2ExtMulLowI32x4U)               \
  V(I64x2ExtMulHighI32x4U)              \
  V(I32x4Ne)                            \
  V(I32x4GeS)                           \
  V(I32x4GeU)                           \
  V(I32x4ExtMulLowI16x8S)               \
  V(I32x4ExtMulHighI16x8S)              \
  V(I32x4ExtMulLowI16x8U)               \
  V(I32x4ExtMulHighI16x8U)              \
  V(I16x8Ne)                            \
  V(I16x8GeS)                           \
  V(I16x8GeU)                           \
  V(I16x8ExtMulLowI8x16S)               \
  V(I16x8ExtMulHighI8x16S)              \
  V(I16x8ExtMulLowI8x16U)               \
  V(I16x8ExtMulHighI8x16U)              \
  V(I16x8DotI8x16S)                     \
  V(I8x16Ne)                            \
  V(I8x16GeS)                           \
  V(I8x16GeU)                           \
  V(I8x16Swizzle)

#define PROTOTYPE_SIMD_BINOP_WITH_SCRATCH(name)                              \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2, \
            Simd128Register scratch);
  SIMD_BINOP_WITH_SCRATCH_LIST(PROTOTYPE_SIMD_BINOP_WITH_SCRATCH)
#undef PROTOTYPE_SIMD_BINOP_WITH_SCRATCH
#undef SIMD_BINOP_WITH_SCRATCH_LIST

#define SIMD_SHIFT_LIST(V) \
  V(I64x2Shl)              \
  V(I64x2ShrS)             \
  V(I64x2ShrU)             \
  V(I32x4Shl)              \
  V(I32x4ShrS)             \
  V(I32x4ShrU)             \
  V(I16x8Shl)              \
  V(I16x8ShrS)             \
  V(I16x8ShrU)             \
  V(I8x16Shl)              \
  V(I8x16ShrS)             \
  V(I8x16ShrU)

#define PROTOTYPE_SIMD_SHIFT(name)                                          \
  void name(Simd128Register dst, Simd128Register src1, Register src2,       \
            Simd128Register scratch);                                       \
  void name(Simd128Register dst, Simd128Register src1, const Operand& src2, \
            Register scratch1, Simd128Register scratch2);
  SIMD_SHIFT_LIST(PROTOTYPE_SIMD_SHIFT)
#undef PROTOTYPE_SIMD_SHIFT
#undef SIMD_SHIFT_LIST

#define SIMD_BITMASK_LIST(V) \
  V(I64x2BitMask)            \
  V(I32x4BitMask)            \
  V(I16x8BitMask)

#define PROTOTYPE_SIMD_BITMASK(name)                              \
  void name(Register dst, Simd128Register src, Register scratch1, \
            Simd128Register scratch2);
  SIMD_BITMASK_LIST(PROTOTYPE_SIMD_BITMASK)
#undef PROTOTYPE_SIMD_BITMASK
#undef SIMD_BITMASK_LIST

#define SIMD_UNOP_LIST(V)   \
  V(F64x2Abs)               \
  V(F64x2Neg)               \
  V(F64x2Sqrt)              \
  V(F64x2Ceil)              \
  V(F64x2Floor)             \
  V(F64x2Trunc)             \
  V(F64x2PromoteLowF32x4)   \
  V(F32x4Abs)               \
  V(F32x4Neg)               \
  V(F32x4Sqrt)              \
  V(F32x4Ceil)              \
  V(F32x4Floor)             \
  V(F32x4Trunc)             \
  V(F32x4SConvertI32x4)     \
  V(F32x4UConvertI32x4)     \
  V(I64x2Neg)               \
  V(F64x2ConvertLowI32x4S)  \
  V(I64x2SConvertI32x4Low)  \
  V(I64x2SConvertI32x4High) \
  V(I32x4Neg)               \
  V(I32x4SConvertI16x8Low)  \
  V(I32x4SConvertI16x8High) \
  V(I32x4UConvertF32x4)     \
  V(I16x8SConvertI8x16Low)  \
  V(I16x8SConvertI8x16High) \
  V(I8x16Popcnt)            \
  V(S128Not)

#define PROTOTYPE_SIMD_UNOP(name) \
  void name(Simd128Register dst, Simd128Register src);
  SIMD_UNOP_LIST(PROTOTYPE_SIMD_UNOP)
#undef PROTOTYPE_SIMD_UNOP
#undef SIMD_UNOP_LIST

#define SIMD_UNOP_WITH_SCRATCH_LIST(V) \
  V(F32x4DemoteF64x2Zero)              \
  V(I64x2Abs)                          \
  V(I32x4Abs)                          \
  V(I32x4SConvertF32x4)                \
  V(I32x4TruncSatF64x2SZero)           \
  V(I32x4TruncSatF64x2UZero)           \
  V(I16x8Abs)                          \
  V(I16x8Neg)                          \
  V(I8x16Abs)                          \
  V(I8x16Neg)

#define PROTOTYPE_SIMD_UNOP_WITH_SCRATCH(name) \
  void name(Simd128Register dst, Simd128Register src, Simd128Register scratch);
  SIMD_UNOP_WITH_SCRATCH_LIST(PROTOTYPE_SIMD_UNOP_WITH_SCRATCH)
#undef PROTOTYPE_SIMD_UNOP_WITH_SCRATCH
#undef SIMD_UNOP_WITH_SCRATCH_LIST

#define SIMD_ALL_TRUE_LIST(V) \
  V(I64x2AllTrue)             \
  V(I32x4AllTrue)             \
  V(I16x8AllTrue)             \
  V(I8x16AllTrue)

#define PROTOTYPE_SIMD_ALL_TRUE(name)                             \
  void name(Register dst, Simd128Register src, Register scratch1, \
            Register scratch2, Simd128Register scratch3);
  SIMD_ALL_TRUE_LIST(PROTOTYPE_SIMD_ALL_TRUE)
#undef PROTOTYPE_SIMD_ALL_TRUE
#undef SIMD_ALL_TRUE_LIST

#define SIMD_QFM_LIST(V) \
  V(F64x2Qfma)           \
  V(F64x2Qfms)           \
  V(F32x4Qfma)           \
  V(F32x4Qfms)
#define PROTOTYPE_SIMD_QFM(name)                                             \
  void name(Simd128Register dst, Simd128Register src1, Simd128Register src2, \
            Simd128Register src3, Simd128Register scratch);
  SIMD_QFM_LIST(PROTOTYPE_SIMD_QFM)
#undef PROTOTYPE_SIMD_QFM
#undef SIMD_QFM_LIST

#define SIMD_EXT_ADD_PAIRWISE_LIST(V) \
  V(I32x4ExtAddPairwiseI16x8S)        \
  V(I32x4ExtAddPairwiseI16x8U)        \
  V(I16x8ExtAddPairwiseI8x16S)        \
  V(I16x8ExtAddPairwiseI8x16U)
#define PROTOTYPE_SIMD_EXT_ADD_PAIRWISE(name)         \
  void name(Simd128Register dst, Simd128Register src, \
            Simd128Register scratch1, Simd128Register scratch2);
  SIMD_EXT_ADD_PAIRWISE_LIST(PROTOTYPE_SIMD_EXT_ADD_PAIRWISE)
#undef PROTOTYPE_SIMD_EXT_ADD_PAIRWISE
#undef SIMD_EXT_ADD_PAIRWISE_LIST

  void LoadSimd128(Simd128Register dst, const MemOperand& mem,
                   Register scratch);
  void StoreSimd128(Simd128Register src, const MemOperand& mem,
                    Register scratch);
  void LoadSimd128LE(Simd128Register dst, const MemOperand& mem,
                     Register scratch);
  void StoreSimd128LE(Simd128Register src, const MemOperand& mem,
                      Register scratch1, Simd128Register scratch2);
  void LoadSimd128Uint64(Simd128Register reg, const MemOperand& mem,
                         Register scratch);
  void LoadSimd128Uint32(Simd128Register reg, const MemOperand& mem,
                         Register scratch);
  void LoadSimd128Uint16(Simd128Register reg, const MemOperand& mem,
                         Register scratch);
  void LoadSimd128Uint8(Simd128Register reg, const MemOperand& mem,
                        Register scratch);
  void StoreSimd128Uint64(Simd128Register reg, const MemOperand& mem,
                          Register scratch);
  void StoreSimd128Uint32(Simd128Register reg, const MemOperand& mem,
                          Register scratch);
  void StoreSimd128Uint16(Simd128Register reg, const MemOperand& mem,
                          Register scratch);
  void StoreSimd128Uint8(Simd128Register reg, const MemOperand& mem,
                         Register scratch);
  void LoadLane64LE(Simd128Register dst, const MemOperand& mem, int lane,
                    Register scratch1, Simd128Register scratch2);
  void LoadLane32LE(Simd128Register dst, const MemOperand& mem, int lane,
                    Register scratch1, Simd128Register scratch2);
  void LoadLane16LE(Simd128Register dst, const MemOperand& mem, int lane,
                    Register scratch1, Simd128Register scratch2);
  void LoadLane8LE(Simd128Register dst, const MemOperand& mem, int lane,
                   Register scratch1, Simd128Register scratch2);
  void StoreLane64LE(Simd128Register src, const MemOperand& mem, int lane,
                     Register scratch1, Simd128Register scratch2);
  void StoreLane32LE(Simd128Register src, const MemOperand& mem, int lane,
                     Register scratch1, Simd128Register scratch2);
  void StoreLane16LE(Simd128Register src, const MemOperand& mem, int lane,
                     Register scratch1, Simd128Register scratch2);
  void StoreLane8LE(Simd128Register src, const MemOperand& mem, int lane,
                    Register scratch1, Simd128Register scratch2);
  void LoadAndSplat64x2LE(Simd128Register dst, const MemOperand& mem,
                          Register scratch);
  void LoadAndSplat32x4LE(Simd128Register dst, const MemOperand& mem,
                          Register scratch);
  void LoadAndSplat16x8LE(Simd128Register dst, const MemOperand& me,
                          Register scratch);
  void LoadAndSplat8x16LE(Simd128Register dst, const MemOperand& mem,
                          Register scratch);
  void LoadAndExtend32x2SLE(Simd128Register dst, const MemOperand& mem,
                            Register scratch);
  void LoadAndExtend32x2ULE(Simd128Register dst, const MemOperand& mem,
                            Register scratch1, Simd128Register scratch2);
  void LoadAndExtend16x4SLE(Simd128Register dst, const MemOperand& mem,
                            Register scratch);
  void LoadAndExtend16x4ULE(Simd128Register dst, const MemOperand& mem,
                            Register scratch1, Simd128Register scratch2);
  void LoadAndExtend8x8SLE(Simd128Register dst, const MemOperand& mem,
                           Register scratch);
  void LoadAndExtend8x8ULE(Simd128Register dst, const MemOperand& mem,
                           Register scratch1, Simd128Register scratch2);
  void LoadV64ZeroLE(Simd128Register dst, const MemOperand& mem,
                     Register scratch1, Simd128Register scratch2);
  void LoadV32ZeroLE(Simd128Register dst, const MemOperand& mem,
                     Register scratch1, Simd128Register scratch2);
  void F64x2Splat(Simd128Register dst, DoubleRegister src, Register scratch);
  void F32x4Splat(Simd128Register dst, DoubleRegister src,
                  DoubleRegister scratch1, Register scratch2);
  void I64x2Splat(Simd128Register dst, Register src);
  void I32x4Splat(Simd128Register dst, Register src);
  void I16x8Splat(Simd128Register dst, Register src);
  void I8x16Splat(Simd128Register dst, Register src);
  void F64x2ExtractLane(DoubleRegister dst, Simd128Register src,
                        uint8_t imm_lane_idx, Simd128Register scratch1,
                        Register scratch2);
  void F32x4ExtractLane(DoubleRegister dst, Simd128Register src,
                        uint8_t imm_lane_idx, Simd128Register scratch1,
                        Register scratch2, Register scratch3);
  void I64x2ExtractLane(Register dst, Simd128Register src, uint8_t imm_lane_idx,
                        Simd128Register scratch);
  void I32x4ExtractLane(Register dst, Simd128Register src, uint8_t imm_lane_idx,
                        Simd128Register scratch);
  void I16x8ExtractLaneU(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Simd128Register scratch);
  void I16x8ExtractLaneS(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Simd128Register scratch);
  void I8x16ExtractLaneU(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Simd128Register scratch);
  void I8x16ExtractLaneS(Register dst, Simd128Register src,
                         uint8_t imm_lane_idx, Simd128Register scratch);
  void F64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                        DoubleRegister src2, uint8_t imm_lane_idx,
                        Register scratch1, Simd128Register scratch2);
  void F32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                        DoubleRegister src2, uint8_t imm_lane_idx,
                        Register scratch1, DoubleRegister scratch2,
                        Simd128Register scratch3);
  void I64x2ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx,
                        Simd128Register scratch);
  void I32x4ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx,
                        Simd128Register scratch);
  void I16x8ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx,
                        Simd128Register scratch);
  void I8x16ReplaceLane(Simd128Register dst, Simd128Register src1,
                        Register src2, uint8_t imm_lane_idx,
                        Simd128Register scratch);
  void I64x2Mul(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Register scratch1, Register scrahc2, Register scratch3,
                Simd128Register scratch4);
  void F64x2Min(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Simd128Register scratch1, Simd128Register scratch2);
  void F64x2Max(Simd128Register dst, Simd128Register src1, Simd128Register src2,
                Simd128Register scratch1, Simd128Register scratch2);
  void F64x2ConvertLowI32x4U(Simd128Register dst, Simd128Register src,
                             Register scratch1, Simd128Register scratch2);
  void I64x2UConvertI32x4Low(Simd128Register dst, Simd128Register src,
                             Register scratch1, Simd128Register scratch2);
  void I64x2UConvertI32x4High(Simd128Register dst, Simd128Register src,
                              Register scratch1, Simd128Register scratch2);
  void I32x4UConvertI16x8Low(Simd128Register dst, Simd128Register src,
                             Register scratch1, Simd128Register scratch2);
  void I32x4UConvertI16x8High(Simd128Register dst, Simd128Register src,
                              Register scratch1, Simd128Register scratch2);
  void I16x8UConvertI8x16Low(Simd128Register dst, Simd128Register src,
                             Register scratch1, Simd128Register scratch2);
  void I16x8UConvertI8x16High(Simd128Register dst, Simd128Register src,
                              Register scratch1, Simd128Register scratch2);
  void I8x16BitMask(Register dst, Simd128Register src, Register scratch1,
                    Register scratch2, Simd128Register scratch3);
  void I8x16Shuffle(Simd128Register dst, Simd128Register src1,
                    Simd128Register src2, uint64_t high, uint64_t low,
                    Register scratch1, Register scratch2,
                    Simd128Register scratch3);
  void I32x4DotI8x16AddS(Simd128Register dst, Simd128Regist
"""


```