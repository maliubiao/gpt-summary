Response:
The user wants a summary of the functionalities provided by the C++ header file `v8/src/codegen/riscv/macro-assembler-riscv.h`.

Here's a plan to achieve that:

1. **Identify the core purpose:**  The file name suggests it's a macro assembler for the RISC-V architecture within the V8 JavaScript engine. This means it provides higher-level abstractions over raw RISC-V assembly instructions.

2. **Categorize the functionalities:** Scan through the provided code snippet and group the methods based on their apparent function. Some likely categories include:
    * Bit manipulation
    * Floating-point operations
    * Endianness conversion
    * Unaligned memory access
    * Load/store operations (various sizes and signedness)
    * Root table access
    * Pointer compression (if applicable)
    * V8 sandbox support (if applicable)
    * Control flow (jumps, calls)
    * SIMD/Vector operations (RVV)
    * Stack frame manipulation
    * Context and global object access
    * Optimized code loading
    * Function invocation
    * GC support

3. **Summarize each category:** Briefly describe the purpose of the methods within each category.

4. **Address specific questions:**
    * **.tq extension:** State that the file does *not* have a `.tq` extension and therefore is not a Torque file.
    * **Relationship to JavaScript:** Explain that this header provides the low-level building blocks for V8's RISC-V code generation, which directly executes JavaScript. Give a conceptual JavaScript example that would involve these low-level operations (e.g., accessing object properties, arithmetic operations).
    * **Code logic inference:** Choose a simple method (like `ExtractBits`) and provide an example of input registers/values and the expected output.
    * **Common programming errors:** Think about potential errors related to memory access, register usage, or incorrect assumptions about data types.
    * **Overall function:** Provide a concise summary of the header file's role.
这是 `v8/src/codegen/riscv/macro-assembler-riscv.h` 文件第二部分的总结，它延续了第一部分的功能，主要提供了用于在 RISC-V 架构上生成机器码的宏汇编器接口。  以下是其功能的归纳：

**核心功能延续：提供 RISC-V 架构的宏汇编指令，简化机器码生成**

这部分代码继续定义了一系列 C++ 方法，这些方法是对 RISC-V 汇编指令的更高层次抽象。 开发者可以使用这些方法来生成执行特定操作的机器码，而无需直接编写底层的汇编指令。

**主要功能点包括：**

1. **位操作 (Bit Manipulation):**
   - `ExtractBits`: 从寄存器中提取指定位置和大小的位，可以选择是否进行符号扩展。
   - `InsertBits`: 将源寄存器的指定位插入到目标寄存器的指定位置。

2. **浮点运算 (Floating-Point Operations):**
   - `Neg_s`, `Neg_d`: 计算单精度和双精度浮点数的负数。
   - `Clear_if_nan_d`, `Clear_if_nan_s`: 如果浮点数为 NaN，则清除目标寄存器。
   - `Trunc_uw_s`: 将单精度浮点数转换为无符号整数。
   - 提供了各种浮点数和整数之间的类型转换宏 (`Cvt_d_uw`, `Cvt_d_w`, `Cvt_s_uw`, `Cvt_s_w`, `Trunc_uw_d`, `Trunc_w_d`, 等等)。
   - 提供了浮点数的舍入操作 (`Trunc_d_d`, `Round_d_d`, `Floor_d_d`, `Ceil_d_d`, `Trunc_s_s`, `Round_s_s`, `Floor_s_s`, `Ceil_s_s`)。
   - 提供了浮点数的最大值和最小值操作 (`Float32Max`, `Float32Min`, `Float64Max`, `Float64Min`)。
   - 针对 RISC-V Vector Extension (RVV) 提供了浮点数的舍入操作 (`Ceil_f`, `Ceil_d`, `Floor_f`, `Floor_d`, `Trunc_f`, `Trunc_d`, `Round_f`, `Round_d`)。
   - 提供了浮点数的乘加和乘减运算 (`Madd_s`, `Madd_d`, `Msub_s`, `Msub_d`)。

3. **字节序转换 (Endianness Conversion):**
   - `ByteSwap`: 改变寄存器中数据的字节序。

4. **非对齐内存访问 (Unaligned Memory Access):**
   - 提供了一系列 `UnalignedLoadHelper` 和 `UnalignedStoreHelper` 模板函数，用于处理非对齐的内存加载和存储操作。
   - 提供了一系列 `Ulh`, `Ulhu`, `Ush`, `Ulw`, `Usw`, `Uld`, `Usd`, `ULoadFloat`, `UStoreFloat`, `ULoadDouble`, `UStoreDouble` 等宏，用于执行非对齐的加载和存储操作。

5. **对齐内存访问 (Aligned Memory Access):**
   - 提供了 `AlignedLoadHelper` 和 `AlignedStoreHelper` 模板函数，用于处理对齐的内存加载和存储操作。

6. **加载/存储宏 (Load/Store Macros):**
   - 提供了一系列 `Lb`, `Lbu`, `Sb`, `Lh`, `Lhu`, `Sh`, `Lw`, `Sw`, `Lwu`, `Ld`, `Sd`, `Lld`, `Scd`, `LoadFloat`, `StoreFloat`, `LoadDouble`, `StoreDouble`, `Ll`, `Sc` 等宏，用于加载和存储不同大小的数据。

7. **条件移动 (Conditional Move):**
   - `MoveIfZero`: 如果指定寄存器的值为零，则将一个寄存器的值移动到另一个寄存器。

8. **寄存器移动 (Register Move):**
   - 提供了 `Move` 宏的多个重载版本，用于在通用寄存器和浮点寄存器之间移动数据。
   - 提供了从浮点寄存器提取高位字和低位字到通用寄存器的宏 (`ExtractHighWordFromF64`, `ExtractLowWordFromF64`)，以及将通用寄存器的值插入到浮点寄存器的高位和低位的宏 (`InsertHighWordF64`, `InsertLowWordF64`)。

9. **加载立即数到浮点寄存器 (Load Immediate to FPR):**
   - `LoadFPRImmediate`: 将浮点数或整数立即数加载到浮点寄存器。

10. **溢出检测 (Overflow Detection):**
    - 提供了 `AddOverflow64`, `SubOverflow64`, `Mulhu32`, `AddOverflow`, `SubOverflow`, `Mulhu`, `MulOverflow32`, `MulOverflow64` 等宏，用于检测算术运算中的溢出。

11. **跳转表生成 (Switch Table Generation):**
    - `GenerateSwitchTable`:  生成用于实现 switch 语句的跳转表。

12. **根表访问 (Root Table Access):**
    - `LoadRoot`, `LoadTaggedRoot`, `LoadCompressedTaggedRoot`: 从根表中加载对象。
    - `LoadMap`, `LoadFeedbackVector`, `LoadCompressedMap`: 加载对象的 Map 和反馈向量。

13. **NaN 规范化 (NaN Canonicalization):**
    - `FPUCanonicalizeNaN`: 将 NaN 值规范化。

14. **Smi (Small Integer) 工具函数:**
    - `SmiTag`: 将整数标记为 Smi。
    - `JumpIfSmi`: 如果寄存器包含 Smi，则跳转。
    - `JumpIfEqual`, `JumpIfLessThan`:  带条件跳转的比较指令。

15. **栈帧操作 (Stack Frame Operations):**
    - `PushStandardFrame`: 推入标准栈帧。
    - `ActivationFrameAlignment`: 获取当前架构的栈帧对齐要求。

16. **地址计算 (Address Calculation):**
    - `CalcScaledAddress`: 计算缩放后的地址。
    - `ComputeCodeStartAddress`: 计算当前代码的起始地址。

17. **可信指针 (Trusted Pointers) 和代码指针 (Code Pointers):**
    - `LoadTrustedPointerField`, `StoreTrustedPointerField`, `LoadCodePointerField`, `StoreCodePointerField`:  用于加载和存储指向可信数据或代码的指针，尤其在启用沙箱模式时。

18. **外部指针 (External Pointers):**
    - `LoadExternalPointerField`: 加载指向外部内存的指针。

19. **指针压缩 (Pointer Compression) (RISC-V 64位):**
    - `LoadTaggedField`, `LoadTaggedFieldWithoutDecompressing`, `LoadTaggedSignedField`, `SmiUntagField`, `StoreTaggedField`, `AtomicStoreTaggedField`, `DecompressTaggedSigned`, `DecompressTagged`, `DecompressProtected`:  用于压缩和解压缩标记指针，以减少内存占用。

20. **V8 沙箱支持 (V8 Sandbox Support) (RISC-V 64位):**
    - `DecodeSandboxedPointer`, `LoadSandboxedPointerField`, `StoreSandboxedPointerField`, `LoadIndirectPointerField`, `StoreIndirectPointerField`, `ResolveIndirectPointerHandle`, `ResolveTrustedPointerHandle`, `ResolveCodePointerHandle`, `LoadCodeEntrypointViaCodePointer`, `AtomicDecompressTaggedSigned`, `AtomicDecompressTagged`:  提供在 V8 沙箱环境中进行指针操作的功能。

21. **比较指令 (Comparison Instructions):**
    - `CmpTagged`: 比较标记指针。

22. **控制流完整性 (Control-Flow Integrity) 相关 (但 RISC-V 不支持):**
    - 定义了一些空的占位符方法，表明 RISC-V 架构目前不支持控制流完整性。

23. **Wasm 与 RVV 的集成 (Wasm into RVV):**
    - `WasmRvvExtractLane`, `WasmRvvEq`, `WasmRvvNe`, `WasmRvvGeS`, `WasmRvvGeU`, `WasmRvvGtS`, `WasmRvvGtU`, `WasmRvvS128const`, `LoadLane`, `StoreLane`: 提供了将 WebAssembly 的 SIMD 操作映射到 RISC-V Vector Extension (RVV) 指令的功能。

24. **接收者加载和存储 (Receiver Load/Store):**
    - `LoadReceiver`, `StoreReceiver`:  用于加载和存储函数调用的接收者对象。

25. **条件跳转辅助函数 (Conditional Jump Helpers):**
    - `IsNear`: 判断跳转目标是否在近距离。

26. **寄存器交换 (Register Swap):**
    - `Swap`: 交换两个寄存器的值。

27. **根对象推送 (Push Root Object):**
    - `PushRoot`: 将根表中的对象推入栈中。

28. **根对象比较和跳转 (Compare Root and Branch):**
    - `CompareRootAndBranch`, `CompareTaggedRootAndBranch`, `JumpIfRoot`, `CompareRoot`, `CompareTaggedRoot`, `JumpIfNotRoot`:  提供与根表中的对象进行比较并根据结果跳转的功能。

29. **类型检查和跳转 (Type Checking and Branching):**
    - `JumpIfIsInRange`, `JumpIfObjectType`, `JumpIfJSAnyIsNotPrimitive`, `JumpIfJSAnyIsPrimitive`:  根据对象的类型或值范围进行条件跳转。

30. **垃圾回收支持 (GC Support):**
    - `RecordWriteField`, `RecordWrite`: 通知垃圾回收器指针写入操作，以维护堆的完整性。

31. **伪指令 (Pseudo-instructions):**
    - `LoadWordPair`, `StoreWordPair`: 加载和存储字对。

32. **栈帧出入 (Enter/Leave Exit Frame):**
    - `EnterExitFrame`, `LeaveExitFrame`:  用于进入和退出 V8 的退出帧，通常在调用外部 C++ 代码时使用。

33. **栈对齐断言 (Stack Alignment Assertion):**
    - `AssertStackIsAligned`: 在调试模式下断言栈是否对齐。

34. **全局代理加载 (Load Global Proxy):**
    - `LoadGlobalProxy`: 加载全局代理对象。

35. **本地上下文槽加载 (Load Native Context Slot):**
    - `LoadNativeContextSlot`: 加载本地上下文中的槽位。

36. **尝试加载优化的 OSR 代码 (Try Load Optimized OSR Code):**
    - `TryLoadOptimizedOsrCode`: 尝试加载并跳转到优化的 On-Stack Replacement (OSR) 代码。

37. **加载全局函数初始 Map (Load Global Function Initial Map):**
    - `LoadGlobalFunctionInitialMap`: 加载全局函数的初始 Map。

38. **JavaScript 调用 (JavaScript Invokes):**
    - `InvokeFunctionCode`, `CheckDebugHook`, `InvokeFunctionWithNewTarget`, `InvokeFunction`:  提供调用 JavaScript 函数的功能，包括处理调试钩子和 new.target。

**关于 .tq 结尾：**

正如你正确指出的，如果 `v8/src/codegen/riscv/macro-assembler-riscv.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。 Torque 是一种用于在 V8 中生成高效 C++ 代码的领域特定语言。 然而，根据你提供的文件名，该文件以 `.h` 结尾，因此是一个 **C++ 头文件**，而不是 Torque 文件。

**与 JavaScript 的关系：**

`macro-assembler-riscv.h` 中定义的宏汇编器直接用于生成执行 JavaScript 代码的机器码。 当 V8 执行 JavaScript 代码时，它会将其编译成机器码，而这个头文件提供的工具正是用于生成这些机器码的关键部分。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
```

当 V8 执行 `add(5, 10)` 时，它会生成类似于以下操作的 RISC-V 机器码 (使用宏汇编器中的宏作为示例)：

```assembly
// 假设 'a' 和 'b' 的值分别在寄存器 r10 和 r11 中
mv  a0, r10  // 将 'a' 的值移动到 a0 寄存器 (通常用于返回值)
add a0, a0, r11 // 将 a0 和 r11 的值相加，结果存回 a0
ret          // 返回
```

`macro-assembler-riscv.h` 中可能包含类似 `Mv(a0, r10)` 和 `Add(a0, a0, r11)` 这样的宏，用于生成上述汇编指令。

**代码逻辑推理示例：**

假设我们调用 `ExtractBits(t0, t1, 2, 3)`，其中：

* **输入:**
    * `rt` (t0) 是目标寄存器。
    * `rs` (t1) 是源寄存器，假设其值为二进制 `0b11010110`.
    * `pos` 是 2。
    * `size` 是 3。
    * `sign_extend` 默认为 `false`。

* **代码逻辑:**  从 `rs` (t1) 的第 2 位开始提取 3 位。第 2 位是右起第三位 (从 0 开始计数)。所以要提取的位是 `010`。

* **输出:**
    * `rt` (t0) 的值将变为 `0b00000010` (因为 `sign_extend` 为 `false`，所以高位补零)。

**用户常见的编程错误示例：**

使用宏汇编器时，常见的编程错误包括：

1. **寄存器使用冲突：**  错误地使用了已经被其他操作使用的寄存器，导致数据被意外覆盖。例如，在一个复杂的计算过程中，忘记保存中间结果的寄存器，并在后续操作中错误地使用了它。

2. **内存地址计算错误：**  在进行内存访问时，计算的地址不正确，导致读取或写入了错误的内存位置。例如，使用 `MemOperand` 时，偏移量计算错误，或者基址寄存器指向了错误的地址。

3. **类型不匹配：**  在加载或存储数据时，使用了错误的指令或指定了错误的大小，导致数据被截断或解释错误。例如，尝试使用 `Lw` (Load Word - 4字节) 加载一个字节，或者将浮点数存储到整数寄存器中。

4. **未处理的边界情况：**  在位操作或内存访问时，没有考虑到边界情况，例如提取的位数超过了寄存器的大小，或者访问了超出分配内存范围的地址。

**总结:**

`v8/src/codegen/riscv/macro-assembler-riscv.h` 的第二部分继续提供了构建 RISC-V 机器码所需的核心工具，涵盖了位操作、浮点运算、内存访问、控制流、类型转换以及 V8 特有的功能（如根表访问和垃圾回收支持）。 开发者可以使用这些宏来高效地生成针对 RISC-V 架构优化的代码。

Prompt: 
```
这是目录为v8/src/codegen/riscv/macro-assembler-riscv.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/riscv/macro-assembler-riscv.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
ed in rt
  void ExtractBits(Register rt, Register rs, uint16_t pos, uint16_t size,
                   bool sign_extend = false);
  void ExtractBits(Register dest, Register source, Register pos, int size,
                   bool sign_extend = false) {
    sra(dest, source, pos);
    ExtractBits(dest, dest, 0, size, sign_extend);
  }

  // Insert bits [0, size) of source to bits [pos, pos+size) of dest
  void InsertBits(Register dest, Register source, Register pos, int size);

  void Neg_s(FPURegister fd, FPURegister fs);
  void Neg_d(FPURegister fd, FPURegister fs);

  // Change endianness
  void ByteSwap(Register dest, Register src, int operand_size,
                Register scratch = no_reg);

  // helper function for bytes reverse
  template <int NBYTES>
  void ReverseBytesHelper(Register rd, Register rs, Register tmp1,
                          Register tmp2);

  void Clear_if_nan_d(Register rd, FPURegister fs);
  void Clear_if_nan_s(Register rd, FPURegister fs);
  // Convert single to unsigned word.
  void Trunc_uw_s(Register rd, FPURegister fs, Register result = no_reg);

  // helper functions for unaligned load/store
  template <int NBYTES, bool IS_SIGNED>
  void UnalignedLoadHelper(Register rd, const MemOperand& rs);
  template <int NBYTES>
  void UnalignedStoreHelper(Register rd, const MemOperand& rs,
                            Register scratch_other = no_reg);

  template <int NBYTES>
  void UnalignedFLoadHelper(FPURegister frd, const MemOperand& rs,
                            Register scratch);
  template <int NBYTES>
  void UnalignedFStoreHelper(FPURegister frd, const MemOperand& rs,
                             Register scratch);
#if V8_TARGET_ARCH_RISCV32
  void UnalignedDoubleHelper(FPURegister frd, const MemOperand& rs,
                             Register scratch_base);
  void UnalignedDStoreHelper(FPURegister frd, const MemOperand& rs,
                             Register scratch);
#endif

  template <typename Reg_T, typename Func>
  void AlignedLoadHelper(Reg_T target, const MemOperand& rs, Func generator);
  template <typename Reg_T, typename Func>
  void AlignedStoreHelper(Reg_T value, const MemOperand& rs, Func generator);

  template <int NBYTES, bool LOAD_SIGNED>
  void LoadNBytes(Register rd, const MemOperand& rs, Register scratch);
  template <int NBYTES, bool LOAD_SIGNED>
  void LoadNBytesOverwritingBaseReg(const MemOperand& rs, Register scratch0,
                                    Register scratch1);
  // load/store macros
  void Ulh(Register rd, const MemOperand& rs);
  void Ulhu(Register rd, const MemOperand& rs);
  void Ush(Register rd, const MemOperand& rs);

  void Ulw(Register rd, const MemOperand& rs);
  void Usw(Register rd, const MemOperand& rs);

  void Uld(Register rd, const MemOperand& rs);
  void Usd(Register rd, const MemOperand& rs);

  void ULoadFloat(FPURegister fd, const MemOperand& rs, Register scratch);
  void UStoreFloat(FPURegister fd, const MemOperand& rs, Register scratch);

  void ULoadDouble(FPURegister fd, const MemOperand& rs, Register scratch);
  void UStoreDouble(FPURegister fd, const MemOperand& rs, Register scratch);

  using Trapper = std::function<void(int)>;

  void Lb(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Lbu(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Sb(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});

  void Lh(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Lhu(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Sh(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});

  void Lw(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Sw(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});

#if V8_TARGET_ARCH_RISCV64
  void Ulwu(Register rd, const MemOperand& rs);
  void Lwu(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Ld(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Sd(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Lld(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Scd(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});

  inline void Load32U(Register rd, const MemOperand& rs,
                      Trapper&& trapper = [](int){}) {
    Lwu(rd, rs, std::forward<Trapper>(trapper));
  }
  inline void LoadWord(Register rd, const MemOperand& rs,
                       Trapper&& trapper = [](int){}) {
    Ld(rd, rs, std::forward<Trapper>(trapper));
  }
  inline void StoreWord(Register rd, const MemOperand& rs,
                        Trapper&& trapper = [](int){}) {
    Sd(rd, rs, std::forward<Trapper>(trapper));
  }
#elif V8_TARGET_ARCH_RISCV32
  inline void Load32U(
      Register rd, const MemOperand& rs, Trapper&& trapper = [](int){}) {
    Lw(rd, rs, std::forward<Trapper>(trapper));
  }
  inline void LoadWord(
      Register rd, const MemOperand& rs, Trapper&& trapper = [](int){}) {
    Lw(rd, rs, std::forward<Trapper>(trapper));
  }
  inline void StoreWord(
      Register rd, const MemOperand& rs, Trapper&& trapper = [](int){}) {
    Sw(rd, rs, std::forward<Trapper>(trapper));
  }
#endif
  void LoadFloat(
      FPURegister fd, const MemOperand& src, Trapper&& trapper = [](int){});
  void StoreFloat(
      FPURegister fs, const MemOperand& dst, Trapper&& trapper = [](int){});

  void LoadDouble(
      FPURegister fd, const MemOperand& src, Trapper&& trapper = [](int){});
  void StoreDouble(
      FPURegister fs, const MemOperand& dst, Trapper&& trapper = [](int){});

  void Ll(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});
  void Sc(Register rd, const MemOperand& rs, Trapper&& trapper = [](int){});

  void Float32Max(FPURegister dst, FPURegister src1, FPURegister src2);
  void Float32Min(FPURegister dst, FPURegister src1, FPURegister src2);
  void Float64Max(FPURegister dst, FPURegister src1, FPURegister src2);
  void Float64Min(FPURegister dst, FPURegister src1, FPURegister src2);
  template <typename F>
  void FloatMinMaxHelper(FPURegister dst, FPURegister src1, FPURegister src2,
                         MaxMinKind kind);

  bool IsDoubleZeroRegSet() { return has_double_zero_reg_set_; }
  bool IsSingleZeroRegSet() { return has_single_zero_reg_set_; }

  inline void MoveIfZero(Register rd, Register rj, Register rk) {
    CHECK(CpuFeatures::IsSupported(ZICOND));
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    czero_nez(scratch, rj, rk);
    czero_eqz(rd, rd, rk);
    or_(rd, rd, scratch);
  }

  inline void Move(Register dst, Tagged<Smi> smi) { li(dst, Operand(smi)); }

  inline void Move(Register dst, Register src) {
    if (dst != src) {
      mv(dst, src);
    }
  }

  inline void MoveDouble(FPURegister dst, FPURegister src) {
    if (dst != src) fmv_d(dst, src);
  }

  inline void MoveFloat(FPURegister dst, FPURegister src) {
    if (dst != src) fmv_s(dst, src);
  }

  inline void Move(FPURegister dst, FPURegister src) { MoveDouble(dst, src); }

#if V8_TARGET_ARCH_RISCV64
  inline void Move(Register dst_low, Register dst_high, FPURegister src) {
    fmv_x_d(dst_high, src);
    fmv_x_w(dst_low, src);
    srli(dst_high, dst_high, 32);
  }

  inline void Move(Register dst, FPURegister src) { fmv_x_d(dst, src); }

  inline void Move(FPURegister dst, Register src) { fmv_d_x(dst, src); }
#elif V8_TARGET_ARCH_RISCV32
  inline void Move(Register dst, FPURegister src) { fmv_x_w(dst, src); }

  inline void Move(FPURegister dst, Register src) { fmv_w_x(dst, src); }
#endif

  // Extract sign-extended word from high-half of FPR to GPR
  inline void ExtractHighWordFromF64(Register dst_high, FPURegister src) {
#if V8_TARGET_ARCH_RISCV64
    fmv_x_d(dst_high, src);
    srai(dst_high, dst_high, 32);
#elif V8_TARGET_ARCH_RISCV32
    // todo(riscv32): delete storedouble
    AddWord(sp, sp, Operand(-8));
    StoreDouble(src, MemOperand(sp, 0));
    Lw(dst_high, MemOperand(sp, 4));
    AddWord(sp, sp, Operand(8));
#endif
  }

  // Insert low-word from GPR (src_high) to the high-half of FPR (dst)
  void InsertHighWordF64(FPURegister dst, Register src_high);

  // Extract sign-extended word from low-half of FPR to GPR
  inline void ExtractLowWordFromF64(Register dst_low, FPURegister src) {
    fmv_x_w(dst_low, src);
  }

  // Insert low-word from GPR (src_high) to the low-half of FPR (dst)
  void InsertLowWordF64(FPURegister dst, Register src_low);

  void LoadFPRImmediate(FPURegister dst, float imm) {
    LoadFPRImmediate(dst, base::bit_cast<uint32_t>(imm));
  }
  void LoadFPRImmediate(FPURegister dst, double imm) {
    LoadFPRImmediate(dst, base::bit_cast<uint64_t>(imm));
  }
  void LoadFPRImmediate(FPURegister dst, uint32_t src);
  void LoadFPRImmediate(FPURegister dst, uint64_t src);
#if V8_TARGET_ARCH_RISCV64
  // AddOverflow64 sets overflow register to a negative value if
  // overflow occured, otherwise it is zero or positive
  void AddOverflow64(Register dst, Register left, const Operand& right,
                     Register overflow);
  // SubOverflow64 sets overflow register to a negative value if
  // overflow occured, otherwise it is zero or positive
  void SubOverflow64(Register dst, Register left, const Operand& right,
                     Register overflow);
  // MIPS-style 32-bit unsigned mulh
  void Mulhu32(Register dst, Register left, const Operand& right,
               Register left_zero, Register right_zero);
#elif V8_TARGET_ARCH_RISCV32
  // AddOverflow sets overflow register to a negative value if
  // overflow occured, otherwise it is zero or positive
  void AddOverflow(Register dst, Register left, const Operand& right,
                   Register overflow);
  // SubOverflow sets overflow register to a negative value if
  // overflow occured, otherwise it is zero or positive
  void SubOverflow(Register dst, Register left, const Operand& right,
                   Register overflow);
  // MIPS-style 32-bit unsigned mulh
  void Mulhu(Register dst, Register left, const Operand& right,
             Register left_zero, Register right_zero);
#endif
  // MulOverflow32 sets overflow register to zero if no overflow occured
  void MulOverflow32(Register dst, Register left, const Operand& right,
                     Register overflow);
  // MulOverflow64 sets overflow register to zero if no overflow occured
  void MulOverflow64(Register dst, Register left, const Operand& right,
                     Register overflow);
  // Number of instructions needed for calculation of switch table entry address
  static const int kSwitchTablePrologueSize = 6;

  // GetLabelFunction must be lambda '[](size_t index) -> Label*' or a
  // functor/function with 'Label *func(size_t index)' declaration.
  template <typename Func>
  void GenerateSwitchTable(Register index, size_t case_count,
                           Func GetLabelFunction);

  // Load an object from the root table.
  void LoadRoot(Register destination, RootIndex index) final;
  void LoadTaggedRoot(Register destination, RootIndex index);
  void LoadCompressedTaggedRoot(Register destination, RootIndex index);

  void LoadMap(Register destination, Register object);

  void LoadFeedbackVector(Register dst, Register closure, Register scratch,
                          Label* fbv_undef);
  void LoadCompressedMap(Register dst, Register object);

  // If the value is a NaN, canonicalize the value else, do nothing.
  void FPUCanonicalizeNaN(const DoubleRegister dst, const DoubleRegister src);

  // ---------------------------------------------------------------------------
  // FPU macros. These do not handle special cases like NaN or +- inf.

  // Convert unsigned word to double.
  void Cvt_d_uw(FPURegister fd, Register rs);

  // convert signed word to double.
  void Cvt_d_w(FPURegister fd, Register rs);

  // Convert unsigned long to double.
  void Cvt_d_ul(FPURegister fd, Register rs);

  // Convert unsigned word to float.
  void Cvt_s_uw(FPURegister fd, Register rs);

  // convert signed word to float.
  void Cvt_s_w(FPURegister fd, Register rs);

  // Convert unsigned long to float.
  void Cvt_s_ul(FPURegister fd, Register rs);

  // Convert double to unsigned word.
  void Trunc_uw_d(Register rd, FPURegister fs, Register result = no_reg);

  // Convert double to signed word.
  void Trunc_w_d(Register rd, FPURegister fs, Register result = no_reg);

  // Convert single to signed word.
  void Trunc_w_s(Register rd, FPURegister fs, Register result = no_reg);
#if V8_TARGET_ARCH_RISCV64
  // Convert double to unsigned long.
  void Trunc_ul_d(Register rd, FPURegister fs, Register result = no_reg);

  // Convert singled to signed long.
  void Trunc_l_d(Register rd, FPURegister fs, Register result = no_reg);

  // Convert single to unsigned long.
  void Trunc_ul_s(Register rd, FPURegister fs, Register result = no_reg);

  // Convert singled to signed long.
  void Trunc_l_s(Register rd, FPURegister fs, Register result = no_reg);

  // Round double functions
  void Trunc_d_d(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
  void Round_d_d(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
  void Floor_d_d(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
  void Ceil_d_d(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
#endif
  // Round single to signed word.
  void Round_w_s(Register rd, FPURegister fs, Register result = no_reg);

  // Round double to signed word.
  void Round_w_d(Register rd, FPURegister fs, Register result = no_reg);

  // Ceil single to signed word.
  void Ceil_w_s(Register rd, FPURegister fs, Register result = no_reg);

  // Ceil double to signed word.
  void Ceil_w_d(Register rd, FPURegister fs, Register result = no_reg);

  // Floor single to signed word.
  void Floor_w_s(Register rd, FPURegister fs, Register result = no_reg);

  // Floor double to signed word.
  void Floor_w_d(Register rd, FPURegister fs, Register result = no_reg);

  // Round float functions
  void Trunc_s_s(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
  void Round_s_s(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
  void Floor_s_s(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);
  void Ceil_s_s(FPURegister fd, FPURegister fs, FPURegister fpu_scratch);

  void Ceil_f(VRegister dst, VRegister src, Register scratch,
              VRegister v_scratch);

  void Ceil_d(VRegister dst, VRegister src, Register scratch,
              VRegister v_scratch);

  void Floor_f(VRegister dst, VRegister src, Register scratch,
               VRegister v_scratch);
  void Floor_d(VRegister dst, VRegister src, Register scratch,
               VRegister v_scratch);
  void Trunc_f(VRegister dst, VRegister src, Register scratch,
               VRegister v_scratch);
  void Trunc_d(VRegister dst, VRegister src, Register scratch,
               VRegister v_scratch);
  void Round_f(VRegister dst, VRegister src, Register scratch,
               VRegister v_scratch);
  void Round_d(VRegister dst, VRegister src, Register scratch,
               VRegister v_scratch);
  // -------------------------------------------------------------------------
  // Smi utilities.

  void SmiTag(Register dst, Register src) {
    static_assert(kSmiTag == 0);
#if V8_TARGET_ARCH_RISCV64
    if (SmiValuesAre32Bits()) {
      // Smi goes to upper 32
      slli(dst, src, 32);
    } else {
      DCHECK(SmiValuesAre31Bits());
      // Smi is shifted left by 1
      Add32(dst, src, src);
    }
#elif V8_TARGET_ARCH_RISCV32

    DCHECK(SmiValuesAre31Bits());
    // Smi is shifted left by 1
    slli(dst, src, kSmiShift);
#endif
  }

  void SmiTag(Register reg) { SmiTag(reg, reg); }

  // Jump the register contains a smi.
  void JumpIfSmi(Register value, Label* smi_label,
                 Label::Distance distance = Label::kFar);

  // AssembleArchBinarySearchSwitchRange Use JumpIfEqual and JumpIfLessThan.
  // In V8_COMPRESS_POINTERS, the compare is done with the lower 32 bits of the
  // input.
  void JumpIfEqual(Register a, int32_t b, Label* dest) {
#ifdef V8_COMPRESS_POINTERS
    Sll32(a, a, 0);
#endif
    Branch(dest, eq, a, Operand(b));
  }

  void JumpIfLessThan(Register a, int32_t b, Label* dest) {
#ifdef V8_COMPRESS_POINTERS
    Sll32(a, a, 0);
#endif
    Branch(dest, lt, a, Operand(b));
  }

  // Push a standard frame, consisting of ra, fp, context and JS function.
  void PushStandardFrame(Register function_reg);

  // Get the actual activation frame alignment for target environment.
  static int ActivationFrameAlignment();

  // Calculated scaled address (rd) as rt + rs << sa
  void CalcScaledAddress(Register rd, Register rt, Register rs, uint8_t sa);

  // Compute the start of the generated instruction stream from the current PC.
  // This is an alternative to embedding the {CodeObject} handle as a reference.
  void ComputeCodeStartAddress(Register dst);

  // Load a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  void LoadTrustedPointerField(Register destination, MemOperand field_operand,
                               IndirectPointerTag tag);
  // Store a trusted pointer field.
  void StoreTrustedPointerField(Register value, MemOperand dst_field_operand);
  // Load a code pointer field.
  // These are special versions of trusted pointers that, when the sandbox is
  // enabled, reference code objects through the code pointer table.
  void LoadCodePointerField(Register destination, MemOperand field_operand) {
    LoadTrustedPointerField(destination, field_operand,
                            kCodeIndirectPointerTag);
  }
  // Store a code pointer field.
  void StoreCodePointerField(Register value, MemOperand dst_field_operand) {
    StoreTrustedPointerField(value, dst_field_operand);
  }

  // Loads a field containing an off-heap ("external") pointer and does
  // necessary decoding if sandbox is enabled.
  void LoadExternalPointerField(Register destination, MemOperand field_operand,
                                ExternalPointerTag tag,
                                Register isolate_root = no_reg);

#if V8_TARGET_ARCH_RISCV64
  // ---------------------------------------------------------------------------
  // Pointer compression Support

  // Loads a field containing any tagged value and decompresses it if necessary.
  void LoadTaggedField(const Register& destination,
                       const MemOperand& field_operand,
                       Trapper&& trapper = [](int){});

  // Loads a field containing any tagged value but never decompresses it.
  void LoadTaggedFieldWithoutDecompressing(const Register& destination,
                                           const MemOperand& field_operand);

  // Loads a field containing a tagged signed value and decompresses it if
  // necessary.
  void LoadTaggedSignedField(const Register& destination,
                             const MemOperand& field_operand);

  // Loads a field containing smi value and untags it.
  void SmiUntagField(Register dst, const MemOperand& src);

  // Compresses and stores tagged value to given on-heap location.
  void StoreTaggedField(const Register& value,
                        const MemOperand& dst_field_operand,
                        Trapper&& trapper = [](int){});
  void AtomicStoreTaggedField(Register dst, const MemOperand& src);

  void DecompressTaggedSigned(const Register& destination,
                              const MemOperand& field_operand);
  void DecompressTagged(const Register& destination,
                        const MemOperand& field_operand,
                        Trapper&& trapper = [](int){});
  void DecompressTagged(const Register& destination, const Register& source);
  void DecompressTagged(Register dst, Tagged_t immediate);
  void DecompressProtected(const Register& destination,
                           const MemOperand& field_operand,
                           Trapper&& trapper = [](int){});

  // ---------------------------------------------------------------------------
  // V8 Sandbox support

  // Transform a SandboxedPointer from/to its encoded form, which is used when
  // the pointer is stored on the heap and ensures that the pointer will always
  // point into the sandbox.
  void DecodeSandboxedPointer(Register value);
  void LoadSandboxedPointerField(Register destination,
                                 const MemOperand& field_operand);
  void StoreSandboxedPointerField(Register value,
                                  const MemOperand& dst_field_operand);

  // Loads an indirect pointer field.
  // Only available when the sandbox is enabled, but always visible to avoid
  // having to place the #ifdefs into the caller.
  void LoadIndirectPointerField(Register destination, MemOperand field_operand,
                                IndirectPointerTag tag);
  // Store an indirect pointer field.
  // Only available when the sandbox is enabled, but always visible to avoid
  // having to place the #ifdefs into the caller.
  void StoreIndirectPointerField(Register value, MemOperand dst_field_operand,
                                 Trapper&& trapper = [](int){});

#ifdef V8_ENABLE_SANDBOX
  // Retrieve the heap object referenced by the given indirect pointer handle,
  // which can either be a trusted pointer handle or a code pointer handle.
  void ResolveIndirectPointerHandle(Register destination, Register handle,
                                    IndirectPointerTag tag);

  // Retrieve the heap object referenced by the given trusted pointer handle.
  void ResolveTrustedPointerHandle(Register destination, Register handle,
                                   IndirectPointerTag tag);
  // Retrieve the Code object referenced by the given code pointer handle.
  void ResolveCodePointerHandle(Register destination, Register handle);

  // Load the pointer to a Code's entrypoint via a code pointer.
  // Only available when the sandbox is enabled as it requires the code pointer
  // table.
  void LoadCodeEntrypointViaCodePointer(Register destination,
                                        MemOperand field_operand,
                                        CodeEntrypointTag tag);
#endif

  void AtomicDecompressTaggedSigned(Register dst, const MemOperand& src);
  void AtomicDecompressTagged(Register dst, const MemOperand& src);

  void CmpTagged(const Register& rd, const Register& rs1, const Register& rs2) {
    if (COMPRESS_POINTERS_BOOL) {
      Sub32(rd, rs1, rs2);
    } else {
      SubWord(rd, rs1, rs2);
    }
  }

#elif V8_TARGET_ARCH_RISCV32
  // ---------------------------------------------------------------------------
  // Pointer compression Support
  // rv32 don't support Pointer compression. Defines these functions for
  // simplify builtins.
  inline void LoadTaggedField(const Register& destination,
                              const MemOperand& field_operand,
                              Trapper&& trapper = [](int){}) {
    Lw(destination, field_operand, std::forward<Trapper>(trapper));
  }

  inline void LoadTaggedSignedField(const Register& destination,
                                    const MemOperand& field_operand) {
    Lw(destination, field_operand);
  }

  inline void SmiUntagField(Register dst, const MemOperand& src) {
    SmiUntag(dst, src);
  }

  // Compresses and stores tagged value to given on-heap location.
  void StoreTaggedField(
      const Register& value, const MemOperand& dst_field_operand,
      Trapper&& trapper = [](int){}) {
    Sw(value, dst_field_operand, std::forward<Trapper>(trapper));
  }

  void AtomicStoreTaggedField(Register src, const MemOperand& dst) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    AddWord(scratch, dst.rm(), dst.offset());
    amoswap_w(true, true, zero_reg, src, scratch);
  }
#endif

  // NB: Control-flow integrity (V8_ENABLE_CONTROL_FLOW_INTEGRITY)
  // is not supported for RISC-V.
  //
  // Define a function entrypoint.
  void CodeEntry() {}
  // Define an exception handler.
  void ExceptionHandler() { JumpTarget(); }
  void JumpTarget() {}
  void BindJumpTarget(Label* label) { bind(label); }
  void CallTarget() {}
  void JumpOrCallTarget() {}
  void BindCallTarget(Label* label) { bind(label); }
  void BindJumpOrCallTarget(Label* label) { bind(label); }
  // Define an exception handler and bind a label.
  void BindExceptionHandler(Label* label) { bind(label); }

  // Wasm into RVV
  void WasmRvvExtractLane(Register dst, VRegister src, int8_t idx, VSew sew,
                          Vlmul lmul) {
    VU.set(kScratchReg, sew, lmul);
    VRegister Vsrc = idx != 0 ? kSimd128ScratchReg : src;
    if (idx != 0) {
      vslidedown_vi(kSimd128ScratchReg, src, idx);
    }
    vmv_xs(dst, Vsrc);
  }

  void WasmRvvEq(VRegister dst, VRegister lhs, VRegister rhs, VSew sew,
                 Vlmul lmul);
  void WasmRvvNe(VRegister dst, VRegister lhs, VRegister rhs, VSew sew,
                 Vlmul lmul);
  void WasmRvvGeS(VRegister dst, VRegister lhs, VRegister rhs, VSew sew,
                  Vlmul lmul);
  void WasmRvvGeU(VRegister dst, VRegister lhs, VRegister rhs, VSew sew,
                  Vlmul lmul);
  void WasmRvvGtS(VRegister dst, VRegister lhs, VRegister rhs, VSew sew,
                  Vlmul lmul);
  void WasmRvvGtU(VRegister dst, VRegister lhs, VRegister rhs, VSew sew,
                  Vlmul lmul);

  void WasmRvvS128const(VRegister dst, const uint8_t imms[16]);

  void LoadLane(
      int sz, VRegister dst, uint8_t laneidx, MemOperand src,
      Trapper&& trapper = [](int){});
  void StoreLane(
      int sz, VRegister src, uint8_t laneidx, MemOperand dst,
      Trapper&& trapper = [](int){});

  // It assumes that the arguments are located below the stack pointer.
  void LoadReceiver(Register dest) { LoadWord(dest, MemOperand(sp, 0)); }
  void StoreReceiver(Register rec) { StoreWord(rec, MemOperand(sp, 0)); }

  bool IsNear(Label* L, Condition cond, int rs_reg);

  // Swap two registers.  If the scratch register is omitted then a slightly
  // less efficient form using xor instead of mov is emitted.
  void Swap(Register reg1, Register reg2, Register scratch = no_reg);

  void PushRoot(RootIndex index) {
    UseScratchRegisterScope temps(this);
    Register scratch = temps.Acquire();
    LoadRoot(scratch, index);
    Push(scratch);
  }

  // Compare the object in a register to a value from the root list.
  void CompareRootAndBranch(const Register& obj, RootIndex index, Condition cc,
                            Label* target,
                            ComparisonMode mode = ComparisonMode::kDefault);
  void CompareTaggedRootAndBranch(const Register& with, RootIndex index,
                                  Condition cc, Label* target);
  // Compare the object in a register to a value and jump if they are equal.
  void JumpIfRoot(Register with, RootIndex index, Label* if_equal,
                  Label::Distance distance = Label::kFar) {
    Branch(if_equal, eq, with, index, distance);
  }

  // Compare the object in a register to a value from the root list.
  void CompareRoot(const Register& obj, RootIndex index, const Register& result,
                   ComparisonMode mode = ComparisonMode::kDefault);
  void CompareTaggedRoot(const Register& with, RootIndex index,
                         const Register& result);

  // Compare the object in a register to a value and jump if they are not equal.
  void JumpIfNotRoot(Register with, RootIndex index, Label* if_not_equal,
                     Label::Distance distance = Label::kFar) {
    Branch(if_not_equal, ne, with, index, distance);
  }

  // Checks if value is in range [lower_limit, higher_limit] using a single
  // comparison.
  void JumpIfIsInRange(Register value, unsigned lower_limit,
                       unsigned higher_limit, Label* on_in_range);
  void JumpIfObjectType(Label* target, Condition cc, Register object,
                        InstanceType instance_type, Register scratch = no_reg);
  // Fast check if the object is a js receiver type. Assumes only primitive
  // objects or js receivers are passed.
  void JumpIfJSAnyIsNotPrimitive(
      Register heap_object, Register scratch, Label* target,
      Label::Distance distance = Label::kFar,
      Condition condition = Condition::kUnsignedGreaterThanEqual);
  void JumpIfJSAnyIsPrimitive(Register heap_object, Register scratch,
                              Label* target,
                              Label::Distance distance = Label::kFar) {
    return JumpIfJSAnyIsNotPrimitive(heap_object, scratch, target, distance,
                                     Condition::kUnsignedLessThan);
  }
  // ---------------------------------------------------------------------------
  // GC Support

  // Notify the garbage collector that we wrote a pointer into an object.
  // |object| is the object being stored into, |value| is the object being
  // stored.  value and scratch registers are clobbered by the operation.
  // The offset is the offset from the start of the object, not the offset from
  // the tagged HeapObject pointer.  For use with FieldOperand(reg, off).
  void RecordWriteField(
      Register object, int offset, Register value, RAStatus ra_status,
      SaveFPRegsMode save_fp, SmiCheck smi_check = SmiCheck::kInline,
      SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());

  // For a given |object| notify the garbage collector that the slot |address|
  // has been written.  |value| is the object being stored. The value and
  // address registers are clobbered by the operation.
  void RecordWrite(
      Register object, Operand offset, Register value, RAStatus ra_status,
      SaveFPRegsMode save_fp, SmiCheck smi_check = SmiCheck::kInline,
      SlotDescriptor slot = SlotDescriptor::ForDirectPointerSlot());

  // void Pref(int32_t hint, const MemOperand& rs);

  // ---------------------------------------------------------------------------
  // Pseudo-instructions.

  void LoadWordPair(Register rd, const MemOperand& rs);
  void StoreWordPair(Register rd, const MemOperand& rs);

  void Madd_s(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void Madd_d(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void Msub_s(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);
  void Msub_d(FPURegister fd, FPURegister fr, FPURegister fs, FPURegister ft);

  // stack_space - extra stack space.
  void EnterExitFrame(Register scratch, int stack_space,
                      StackFrame::Type frame_type);
  // Leave the current exit frame.
  void LeaveExitFrame(Register scratch);

  // Make sure the stack is aligned. Only emits code in debug mode.
  void AssertStackIsAligned();

  // Load the global proxy from the current context.
  void LoadGlobalProxy(Register dst) {
    LoadNativeContextSlot(dst, Context::GLOBAL_PROXY_INDEX);
  }

  void LoadNativeContextSlot(Register dst, int index);

  // Falls through and sets scratch_and_result to 0 on failure, jumps to
  // on_result on success.
  void TryLoadOptimizedOsrCode(Register scratch_and_result,
                               CodeKind min_opt_level, Register feedback_vector,
                               FeedbackSlot slot, Label* on_result,
                               Label::Distance distance);

  // Load the initial map from the global function. The registers
  // function and map can be the same, function is then overwritten.
  void LoadGlobalFunctionInitialMap(Register function, Register map,
                                    Register scratch);

  // -------------------------------------------------------------------------
  // JavaScript invokes.

  // Invoke the JavaScript function code by either calling or jumping.
  void InvokeFunctionCode(Register function, Register new_target,
                          Register expected_parameter_count,
                          Register actual_parameter_count, InvokeType type);

  // On function call, call into the debugger if necessary.
  void CheckDebugHook(Register fun, Register new_target,
                      Register expected_parameter_count,
                      Register actual_parameter_count);

  // Invoke the JavaScript function in the given register. Changes the
  // current context to the context in the function before invoking.
  void InvokeFunctionWithNewTarget(Register function, Register new_target,
                                   Register actual_parameter_count,
                                   InvokeType type);
  void InvokeFunction(Register function, Register expected_parameter_count,
                      Register actual_parameter_count, InvokeType type);

  // ---- Ins
"""


```