Response: The user wants a summary of the functionality of the C++ code snippet provided.
The code is part 7 of 8 of a larger file. It's a test file for the ARM64 assembler in V8.
The code consists of various unit tests using the `TEST` macro. These tests primarily verify the correct behavior of the assembler by:
1. **Register Representation:** Testing the properties and methods of register classes (e.g., `VRegister`, `CPURegister`).
2. **Instruction Encoding/Generation:** Testing if specific assembly instructions are generated correctly (though the provided snippet mainly focuses on register properties and some control flow).
3. **Simulator Execution:** Running the generated code in a simulator and checking the resulting register values or memory contents.
4. **Atomic Operations:** Testing the functionality of atomic memory access instructions.
5. **NaN Handling:** Testing the correct propagation and processing of NaN (Not a Number) values in floating-point operations.

Since the user also asked about the relation to JavaScript, I should look for areas where the assembler directly supports features used in JavaScript. While the assembler itself doesn't "know" about JavaScript, it provides the low-level building blocks for the V8 JavaScript engine. For example, floating-point operations, memory access, and atomic operations are all crucial for executing JavaScript code.

I will go through the code block by block to identify the specific functionalities being tested.

**Part 7 Functionality Breakdown:**

* **Register Properties:**  This part continues testing the properties of different register types (scalar and vector, different sizes like B, H, S, D, Q). It checks if methods like `Is8B()`, `IsScalar()`, `IsFPRegister()` return the expected values.
* **Register Creation:** Tests the `VRegister::Create` and `VRegister::...RegFromCode` methods for creating registers with specific sizes and encodings.
* **`IsSameFormat`:** Tests if two vector registers have the same format (size and lane count).
* **`is_valid`:** Checks the `is_valid()` method for different register types, including special registers like `NoReg`, `sp`, `xzr`.
* **`AreConsecutive`:** Tests a utility function to determine if a series of registers are consecutive in their encoding.
* **`CPURegList`:** Tests utility methods for managing lists of CPU registers, including `IncludesAliasOf`, `IsEmpty`, `PopHighestIndex`, `PopLowestIndex`. This is important for things like saving and restoring registers.
* **`Printf` and `PrintfNoPreserve`:** Tests the functionality of printing formatted output, both with and without preserving register values. This is used for debugging and logging within the engine.
* **`blr_lr`:** Tests the "branch to register lr" instruction, fundamental for function calls and returns.
* **`barriers`:** Tests different memory barrier instructions (`DMB`, `DSB`, `ISB`), crucial for ensuring memory ordering in multithreaded scenarios (relevant to JavaScript's concurrency model).
* **Atomic Operations (CAS, CASA, CASL, CASAL, CASB, CASAB, CASLB, CASALB, CASH, CASAH, CASLH, CASALH, CASP, CASPA, CASPL, CASPAL):**  Extensive testing of Compare-and-Swap instructions in different sizes and with acquire/release semantics. These are fundamental building blocks for implementing synchronization primitives, which are used in JavaScript for concurrency and data sharing.
* **Atomic Memory Operations (ADD, CLR, EOR, SET, SMAX, SMIN, UMAX, UMIN, SWP):** Tests a wide range of atomic read-modify-write operations. These are essential for low-level synchronization and data manipulation in multithreaded environments, which is increasingly relevant to JavaScript with the introduction of features like Web Workers and SharedArrayBuffer.
* **NaN Handling (`process_nan_double`, `process_nan_float`, `ProcessNaNsHelper`):** Tests how the assembler handles Not-a-Number values in floating-point operations. This is critical for ensuring correct and predictable behavior in JavaScript numerical computations, as JavaScript uses IEEE 754 floating-point numbers.

**JavaScript Examples:**

1. **Floating-Point Operations and NaN:**

   ```javascript
   let a = 0.0 / 0.0; // NaN
   let b = Math.sqrt(-1); // NaN

   console.log(a + 1); // NaN
   console.log(Math.max(a, 5)); // NaN or 5 depending on specific NaN handling
   ```
   The assembler code tests the low-level implementation of floating-point operations and how NaNs are propagated. V8 needs to ensure that JavaScript's behavior with NaNs matches the IEEE 754 standard.

2. **Atomic Operations and Shared Memory (with SharedArrayBuffer):**

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
   const view = new Int32Array(sab);

   Atomics.add(view, 0, 5); // Low-level "add" operation tested in the C++ code
   Atomics.compareExchange(view, 1, 0, 10); // Related to the CAS instructions tested
   ```
   The C++ atomic operation tests directly relate to the underlying implementation of the `Atomics` API in JavaScript, which allows for safe concurrent access to shared memory.

3. **Memory Barriers (related to concurrency):**

   While not directly exposed in standard JavaScript, memory barriers are essential for ensuring correct memory ordering in concurrent scenarios handled by V8 internally (e.g., in Web Workers or when optimizing concurrent JavaScript code). The `barriers` test in the C++ code ensures that the assembler can generate the necessary instructions for maintaining memory consistency.

In summary, this part of the `test-assembler-arm64.cc` file focuses on verifying the correct implementation of register handling, control flow, atomic memory operations, and NaN propagation within the ARM64 assembler of the V8 JavaScript engine. These low-level functionalities are crucial for the correct and efficient execution of JavaScript code.

这是 `v8/test/cctest/test-assembler-arm64.cc` 文件的第 7 部分，它主要的功能是**测试 ARM64 汇编器的各种指令和功能**。 这一部分着重测试了以下方面：

**1. 寄存器属性和操作:**

* **进一步测试 `VRegister` 类的各种属性和方法**，例如判断寄存器的大小（Is8B, Is16B 等）、类型（IsScalar, IsVector, IsFPRegister 等）、以及是否为特定的寄存器类型 (IsW, IsX, IsV, IsB, IsH, IsS, IsD, IsQ)。
* **测试通过代码创建 `VRegister` 的功能** (`VRegFromCode`) 以及从一个 `VRegister` 获取不同大小的别名寄存器 (`V8B()`, `V16B()`, `V4H()` 等)。
* **测试 `IsSameFormat` 方法**，判断两个向量寄存器是否具有相同的格式。

**2. 寄存器有效性判断:**

* **测试 `is_valid()` 方法**，用于判断寄存器是否有效，包括特殊寄存器 `NoReg`, `NoVReg`, `NoCPUReg` 以及通用寄存器和浮点寄存器。

**3. 判断寄存器是否连续:**

* **测试 `AreConsecutive` 函数**，用于判断一系列寄存器在编码上是否是连续的。这在某些指令中需要连续的寄存器。

**4. `CPURegList` 工具类:**

* **测试 `CPURegList` 工具类的各种功能**，例如添加寄存器、判断是否包含特定寄存器或其别名、判断列表是否为空、以及弹出最高和最低索引的寄存器。这个工具类用于管理一组 CPU 寄存器。

**5. `Printf` 和 `PrintfNoPreserve` 指令:**

* **测试 `Printf` 指令**，它模拟了 C 语言的 `printf` 函数，用于在测试中打印输出，并默认会保存所有寄存器的值。
* **测试 `PrintfNoPreserve` 指令**，它与 `Printf` 类似，但不保证保存所有寄存器的值。测试验证了输出的字符串长度是否正确。

**6. `blr_lr` 指令:**

* **测试 `blr lr` 指令**，这是一个跳转到 `lr` (链接寄存器) 的指令，通常用于函数返回。

**7. 内存屏障指令:**

* **测试各种内存屏障指令 (`Dmb`, `Dsb`, `Isb`)**，用于保证内存操作的顺序性，尤其在多线程环境中非常重要。

**8. 原子操作指令 (CAS, CASA, CASL, CASAL 等):**

* **大量测试各种原子比较并交换指令 (Compare and Swap)**，包括针对字 (`w`)、双字 (`x`)、字节 (`b`)、半字 (`h`) 以及寄存器对 (`p`) 的不同变体，以及带 acquire 和 release 语义的版本 (`Casa`, `Casal`, `Casp` 等)。这些指令用于实现线程同步。

**9. 原子内存操作指令 (ADD, CLR, EOR, SET, SMAX, SMIN, UMAX, UMIN, SWP):**

* **测试各种原子内存操作指令**，例如原子加 (`add`)、清零 (`clr`)、异或 (`eor`)、置位 (`set`)、有符号最大值 (`smax`)、有符号最小值 (`smin`)、无符号最大值 (`umax`)、无符号最小值 (`umin`) 以及交换 (`swp`)。这些指令用于在多线程环境下安全地修改共享内存。

**10. NaN (非数字) 处理:**

* **测试浮点运算中 NaN 值的处理**，包括单精度 (`float`) 和双精度 (`double`) 的 NaN 值，验证了不同指令 (例如 `Fmov`, `Fabs`, `Fneg`, `Fsqrt`, `Frinta`, `Frintn`, `Frintz`, `Fadd`, `Fsub`, `Fmul`, `Fdiv`, `Fmax`, `Fmin`) 如何传播和处理 NaN 值。

**与 JavaScript 的关系 (举例说明):**

虽然这段 C++ 代码是测试 V8 引擎的汇编器，它直接影响着 JavaScript 的执行效率和正确性。以下是一些与 JavaScript 功能相关的例子：

1. **浮点数运算和 NaN:**

   ```javascript
   let a = 0.0 / 0.0; // 结果是 NaN
   let b = Math.sqrt(-1); // 结果是 NaN

   console.log(a + 1); // 输出 NaN
   console.log(Math.max(a, 5)); // 输出 NaN
   ```
   C++ 代码中测试的 NaN 处理确保了 JavaScript 中浮点数运算的正确性，例如 `0.0 / 0.0` 和 `Math.sqrt(-1)` 产生 NaN，并且 NaN 值在后续运算中会按预期传播。

2. **原子操作和共享内存 (SharedArrayBuffer):**

   ```javascript
   const sab = new SharedArrayBuffer(1024);
   const i32a = new Int32Array(sab);

   Atomics.add(i32a, 0, 5); // 原子地将 i32a[0] 的值增加 5
   Atomics.compareExchange(i32a, 1, 0, 10); // 原子地比较 i32a[1] 的值是否为 0，如果是则设置为 10
   ```
   C++ 代码中对原子操作指令的测试直接关系到 JavaScript 中 `Atomics` API 的底层实现。`Atomics` API 允许 JavaScript 在多线程环境下安全地操作共享内存 (`SharedArrayBuffer`)，例如进行原子加、原子比较并交换等操作。

3. **内存屏障:**

   虽然 JavaScript 代码中没有直接的内存屏障概念，但 V8 引擎在执行并发 JavaScript 代码 (例如使用 Web Workers) 时，会使用内存屏障来保证不同线程之间内存操作的可见性和顺序性。C++ 代码中对内存屏障的测试确保了 V8 引擎在底层能够正确地使用这些指令来维护内存一致性。

总而言之，这部分 C++ 测试代码深入地验证了 ARM64 架构下 V8 引擎汇编器的功能，确保了其能够正确地生成执行 JavaScript 代码所需的低级指令，包括浮点数运算、原子操作和内存屏障等关键特性。这些测试对于保证 JavaScript 引擎的正确性、性能和在多线程环境下的稳定性至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-assembler-arm64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共8部分，请归纳一下它的功能
```

### 源代码
```
ormat(kFormat8H));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat4S));
  CHECK_EQ(128U, RegisterSizeInBitsFromFormat(kFormat2D));

  CHECK_EQ(16, LaneCountFromFormat(kFormat16B));
  CHECK_EQ(8, LaneCountFromFormat(kFormat8B));
  CHECK_EQ(8, LaneCountFromFormat(kFormat8H));
  CHECK_EQ(4, LaneCountFromFormat(kFormat4H));
  CHECK_EQ(4, LaneCountFromFormat(kFormat4S));
  CHECK_EQ(2, LaneCountFromFormat(kFormat2S));
  CHECK_EQ(2, LaneCountFromFormat(kFormat2D));
  CHECK_EQ(1, LaneCountFromFormat(kFormat1D));
  CHECK_EQ(1, LaneCountFromFormat(kFormatB));
  CHECK_EQ(1, LaneCountFromFormat(kFormatH));
  CHECK_EQ(1, LaneCountFromFormat(kFormatS));
  CHECK_EQ(1, LaneCountFromFormat(kFormatD));

  CHECK(!IsVectorFormat(kFormatB));
  CHECK(!IsVectorFormat(kFormatH));
  CHECK(!IsVectorFormat(kFormatS));
  CHECK(!IsVectorFormat(kFormatD));
  CHECK(IsVectorFormat(kFormat16B));
  CHECK(IsVectorFormat(kFormat8B));
  CHECK(IsVectorFormat(kFormat8H));
  CHECK(IsVectorFormat(kFormat4H));
  CHECK(IsVectorFormat(kFormat4S));
  CHECK(IsVectorFormat(kFormat2S));
  CHECK(IsVectorFormat(kFormat2D));
  CHECK(IsVectorFormat(kFormat1D));

  CHECK(!d0.Is8B());
  CHECK(!d0.Is16B());
  CHECK(!d0.Is4H());
  CHECK(!d0.Is8H());
  CHECK(!d0.Is2S());
  CHECK(!d0.Is4S());
  CHECK(d0.Is1D());
  CHECK(!d0.Is1S());
  CHECK(!d0.Is1H());
  CHECK(!d0.Is1B());
  CHECK(!d0.IsVector());
  CHECK(d0.IsScalar());
  CHECK(d0.IsFPRegister());

  CHECK(!d0.IsW());
  CHECK(!d0.IsX());
  CHECK(d0.IsV());
  CHECK(!d0.IsB());
  CHECK(!d0.IsH());
  CHECK(!d0.IsS());
  CHECK(d0.IsD());
  CHECK(!d0.IsQ());

  CHECK(!s0.Is8B());
  CHECK(!s0.Is16B());
  CHECK(!s0.Is4H());
  CHECK(!s0.Is8H());
  CHECK(!s0.Is2S());
  CHECK(!s0.Is4S());
  CHECK(!s0.Is1D());
  CHECK(s0.Is1S());
  CHECK(!s0.Is1H());
  CHECK(!s0.Is1B());
  CHECK(!s0.IsVector());
  CHECK(s0.IsScalar());
  CHECK(s0.IsFPRegister());

  CHECK(!s0.IsW());
  CHECK(!s0.IsX());
  CHECK(s0.IsV());
  CHECK(!s0.IsB());
  CHECK(!s0.IsH());
  CHECK(s0.IsS());
  CHECK(!s0.IsD());
  CHECK(!s0.IsQ());

  CHECK(!h0.Is8B());
  CHECK(!h0.Is16B());
  CHECK(!h0.Is4H());
  CHECK(!h0.Is8H());
  CHECK(!h0.Is2S());
  CHECK(!h0.Is4S());
  CHECK(!h0.Is1D());
  CHECK(!h0.Is1S());
  CHECK(h0.Is1H());
  CHECK(!h0.Is1B());
  CHECK(!h0.IsVector());
  CHECK(h0.IsScalar());
  CHECK(!h0.IsFPRegister());

  CHECK(!h0.IsW());
  CHECK(!h0.IsX());
  CHECK(h0.IsV());
  CHECK(!h0.IsB());
  CHECK(h0.IsH());
  CHECK(!h0.IsS());
  CHECK(!h0.IsD());
  CHECK(!h0.IsQ());

  CHECK(!b0.Is8B());
  CHECK(!b0.Is16B());
  CHECK(!b0.Is4H());
  CHECK(!b0.Is8H());
  CHECK(!b0.Is2S());
  CHECK(!b0.Is4S());
  CHECK(!b0.Is1D());
  CHECK(!b0.Is1S());
  CHECK(!b0.Is1H());
  CHECK(b0.Is1B());
  CHECK(!b0.IsVector());
  CHECK(b0.IsScalar());
  CHECK(!b0.IsFPRegister());

  CHECK(!b0.IsW());
  CHECK(!b0.IsX());
  CHECK(b0.IsV());
  CHECK(b0.IsB());
  CHECK(!b0.IsH());
  CHECK(!b0.IsS());
  CHECK(!b0.IsD());
  CHECK(!b0.IsQ());

  CHECK(!q0.Is8B());
  CHECK(!q0.Is16B());
  CHECK(!q0.Is4H());
  CHECK(!q0.Is8H());
  CHECK(!q0.Is2S());
  CHECK(!q0.Is4S());
  CHECK(!q0.Is1D());
  CHECK(!q0.Is2D());
  CHECK(!q0.Is1S());
  CHECK(!q0.Is1H());
  CHECK(!q0.Is1B());
  CHECK(!q0.IsVector());
  CHECK(q0.IsScalar());
  CHECK(!q0.IsFPRegister());

  CHECK(!q0.IsW());
  CHECK(!q0.IsX());
  CHECK(q0.IsV());
  CHECK(!q0.IsB());
  CHECK(!q0.IsH());
  CHECK(!q0.IsS());
  CHECK(!q0.IsD());
  CHECK(q0.IsQ());

  CHECK(w0.IsW());
  CHECK(!w0.IsX());
  CHECK(!w0.IsV());
  CHECK(!w0.IsB());
  CHECK(!w0.IsH());
  CHECK(!w0.IsS());
  CHECK(!w0.IsD());
  CHECK(!w0.IsQ());

  CHECK(!x0.IsW());
  CHECK(x0.IsX());
  CHECK(!x0.IsV());
  CHECK(!x0.IsB());
  CHECK(!x0.IsH());
  CHECK(!x0.IsS());
  CHECK(!x0.IsD());
  CHECK(!x0.IsQ());

  CHECK(v0.V().IsV());
  CHECK(v0.B().IsB());
  CHECK(v0.H().IsH());
  CHECK(v0.D().IsD());
  CHECK(v0.S().IsS());
  CHECK(v0.Q().IsQ());

  VRegister test_8b(VRegister::Create(0, 64, 8));
  CHECK(test_8b.Is8B());
  CHECK(!test_8b.Is16B());
  CHECK(!test_8b.Is4H());
  CHECK(!test_8b.Is8H());
  CHECK(!test_8b.Is2S());
  CHECK(!test_8b.Is4S());
  CHECK(!test_8b.Is1D());
  CHECK(!test_8b.Is2D());
  CHECK(!test_8b.Is1H());
  CHECK(!test_8b.Is1B());
  CHECK(test_8b.IsVector());
  CHECK(!test_8b.IsScalar());
  CHECK(test_8b.IsFPRegister());

  VRegister test_16b(VRegister::Create(0, 128, 16));
  CHECK(!test_16b.Is8B());
  CHECK(test_16b.Is16B());
  CHECK(!test_16b.Is4H());
  CHECK(!test_16b.Is8H());
  CHECK(!test_16b.Is2S());
  CHECK(!test_16b.Is4S());
  CHECK(!test_16b.Is1D());
  CHECK(!test_16b.Is2D());
  CHECK(!test_16b.Is1H());
  CHECK(!test_16b.Is1B());
  CHECK(test_16b.IsVector());
  CHECK(!test_16b.IsScalar());
  CHECK(!test_16b.IsFPRegister());

  VRegister test_4h(VRegister::Create(0, 64, 4));
  CHECK(!test_4h.Is8B());
  CHECK(!test_4h.Is16B());
  CHECK(test_4h.Is4H());
  CHECK(!test_4h.Is8H());
  CHECK(!test_4h.Is2S());
  CHECK(!test_4h.Is4S());
  CHECK(!test_4h.Is1D());
  CHECK(!test_4h.Is2D());
  CHECK(!test_4h.Is1H());
  CHECK(!test_4h.Is1B());
  CHECK(test_4h.IsVector());
  CHECK(!test_4h.IsScalar());
  CHECK(test_4h.IsFPRegister());

  VRegister test_8h(VRegister::Create(0, 128, 8));
  CHECK(!test_8h.Is8B());
  CHECK(!test_8h.Is16B());
  CHECK(!test_8h.Is4H());
  CHECK(test_8h.Is8H());
  CHECK(!test_8h.Is2S());
  CHECK(!test_8h.Is4S());
  CHECK(!test_8h.Is1D());
  CHECK(!test_8h.Is2D());
  CHECK(!test_8h.Is1H());
  CHECK(!test_8h.Is1B());
  CHECK(test_8h.IsVector());
  CHECK(!test_8h.IsScalar());
  CHECK(!test_8h.IsFPRegister());

  VRegister test_2s(VRegister::Create(0, 64, 2));
  CHECK(!test_2s.Is8B());
  CHECK(!test_2s.Is16B());
  CHECK(!test_2s.Is4H());
  CHECK(!test_2s.Is8H());
  CHECK(test_2s.Is2S());
  CHECK(!test_2s.Is4S());
  CHECK(!test_2s.Is1D());
  CHECK(!test_2s.Is2D());
  CHECK(!test_2s.Is1H());
  CHECK(!test_2s.Is1B());
  CHECK(test_2s.IsVector());
  CHECK(!test_2s.IsScalar());
  CHECK(test_2s.IsFPRegister());

  VRegister test_4s(VRegister::Create(0, 128, 4));
  CHECK(!test_4s.Is8B());
  CHECK(!test_4s.Is16B());
  CHECK(!test_4s.Is4H());
  CHECK(!test_4s.Is8H());
  CHECK(!test_4s.Is2S());
  CHECK(test_4s.Is4S());
  CHECK(!test_4s.Is1D());
  CHECK(!test_4s.Is2D());
  CHECK(!test_4s.Is1S());
  CHECK(!test_4s.Is1H());
  CHECK(!test_4s.Is1B());
  CHECK(test_4s.IsVector());
  CHECK(!test_4s.IsScalar());
  CHECK(!test_4s.IsFPRegister());

  VRegister test_1d(VRegister::Create(0, 64, 1));
  CHECK(!test_1d.Is8B());
  CHECK(!test_1d.Is16B());
  CHECK(!test_1d.Is4H());
  CHECK(!test_1d.Is8H());
  CHECK(!test_1d.Is2S());
  CHECK(!test_1d.Is4S());
  CHECK(test_1d.Is1D());
  CHECK(!test_1d.Is2D());
  CHECK(!test_1d.Is1S());
  CHECK(!test_1d.Is1H());
  CHECK(!test_1d.Is1B());
  CHECK(!test_1d.IsVector());
  CHECK(test_1d.IsScalar());
  CHECK(test_1d.IsFPRegister());

  VRegister test_2d(VRegister::Create(0, 128, 2));
  CHECK(!test_2d.Is8B());
  CHECK(!test_2d.Is16B());
  CHECK(!test_2d.Is4H());
  CHECK(!test_2d.Is8H());
  CHECK(!test_2d.Is2S());
  CHECK(!test_2d.Is4S());
  CHECK(!test_2d.Is1D());
  CHECK(test_2d.Is2D());
  CHECK(!test_2d.Is1H());
  CHECK(!test_2d.Is1B());
  CHECK(test_2d.IsVector());
  CHECK(!test_2d.IsScalar());
  CHECK(!test_2d.IsFPRegister());

  VRegister test_1s(VRegister::Create(0, 32, 1));
  CHECK(!test_1s.Is8B());
  CHECK(!test_1s.Is16B());
  CHECK(!test_1s.Is4H());
  CHECK(!test_1s.Is8H());
  CHECK(!test_1s.Is2S());
  CHECK(!test_1s.Is4S());
  CHECK(!test_1s.Is1D());
  CHECK(!test_1s.Is2D());
  CHECK(test_1s.Is1S());
  CHECK(!test_1s.Is1H());
  CHECK(!test_1s.Is1B());
  CHECK(!test_1s.IsVector());
  CHECK(test_1s.IsScalar());
  CHECK(test_1s.IsFPRegister());

  VRegister test_1h(VRegister::Create(0, 16, 1));
  CHECK(!test_1h.Is8B());
  CHECK(!test_1h.Is16B());
  CHECK(!test_1h.Is4H());
  CHECK(!test_1h.Is8H());
  CHECK(!test_1h.Is2S());
  CHECK(!test_1h.Is4S());
  CHECK(!test_1h.Is1D());
  CHECK(!test_1h.Is2D());
  CHECK(!test_1h.Is1S());
  CHECK(test_1h.Is1H());
  CHECK(!test_1h.Is1B());
  CHECK(!test_1h.IsVector());
  CHECK(test_1h.IsScalar());
  CHECK(!test_1h.IsFPRegister());

  VRegister test_1b(VRegister::Create(0, 8, 1));
  CHECK(!test_1b.Is8B());
  CHECK(!test_1b.Is16B());
  CHECK(!test_1b.Is4H());
  CHECK(!test_1b.Is8H());
  CHECK(!test_1b.Is2S());
  CHECK(!test_1b.Is4S());
  CHECK(!test_1b.Is1D());
  CHECK(!test_1b.Is2D());
  CHECK(!test_1b.Is1S());
  CHECK(!test_1b.Is1H());
  CHECK(test_1b.Is1B());
  CHECK(!test_1b.IsVector());
  CHECK(test_1b.IsScalar());
  CHECK(!test_1b.IsFPRegister());

  VRegister test_breg_from_code(VRegister::BRegFromCode(0));
  CHECK_EQ(test_breg_from_code.SizeInBits(), kBRegSizeInBits);

  VRegister test_hreg_from_code(VRegister::HRegFromCode(0));
  CHECK_EQ(test_hreg_from_code.SizeInBits(), kHRegSizeInBits);

  VRegister test_sreg_from_code(VRegister::SRegFromCode(0));
  CHECK_EQ(test_sreg_from_code.SizeInBits(), kSRegSizeInBits);

  VRegister test_dreg_from_code(VRegister::DRegFromCode(0));
  CHECK_EQ(test_dreg_from_code.SizeInBits(), kDRegSizeInBits);

  VRegister test_qreg_from_code(VRegister::QRegFromCode(0));
  CHECK_EQ(test_qreg_from_code.SizeInBits(), kQRegSizeInBits);

  VRegister test_vreg_from_code(VRegister::VRegFromCode(0));
  CHECK_EQ(test_vreg_from_code.SizeInBits(), kVRegSizeInBits);

  VRegister test_v8b(VRegister::VRegFromCode(31).V8B());
  CHECK_EQ(test_v8b.code(), 31);
  CHECK_EQ(test_v8b.SizeInBits(), kDRegSizeInBits);
  CHECK(test_v8b.IsLaneSizeB());
  CHECK(!test_v8b.IsLaneSizeH());
  CHECK(!test_v8b.IsLaneSizeS());
  CHECK(!test_v8b.IsLaneSizeD());
  CHECK_EQ(test_v8b.LaneSizeInBits(), 8U);

  VRegister test_v16b(VRegister::VRegFromCode(31).V16B());
  CHECK_EQ(test_v16b.code(), 31);
  CHECK_EQ(test_v16b.SizeInBits(), kQRegSizeInBits);
  CHECK(test_v16b.IsLaneSizeB());
  CHECK(!test_v16b.IsLaneSizeH());
  CHECK(!test_v16b.IsLaneSizeS());
  CHECK(!test_v16b.IsLaneSizeD());
  CHECK_EQ(test_v16b.LaneSizeInBits(), 8U);

  VRegister test_v4h(VRegister::VRegFromCode(31).V4H());
  CHECK_EQ(test_v4h.code(), 31);
  CHECK_EQ(test_v4h.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v4h.IsLaneSizeB());
  CHECK(test_v4h.IsLaneSizeH());
  CHECK(!test_v4h.IsLaneSizeS());
  CHECK(!test_v4h.IsLaneSizeD());
  CHECK_EQ(test_v4h.LaneSizeInBits(), 16U);

  VRegister test_v8h(VRegister::VRegFromCode(31).V8H());
  CHECK_EQ(test_v8h.code(), 31);
  CHECK_EQ(test_v8h.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v8h.IsLaneSizeB());
  CHECK(test_v8h.IsLaneSizeH());
  CHECK(!test_v8h.IsLaneSizeS());
  CHECK(!test_v8h.IsLaneSizeD());
  CHECK_EQ(test_v8h.LaneSizeInBits(), 16U);

  VRegister test_v2s(VRegister::VRegFromCode(31).V2S());
  CHECK_EQ(test_v2s.code(), 31);
  CHECK_EQ(test_v2s.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v2s.IsLaneSizeB());
  CHECK(!test_v2s.IsLaneSizeH());
  CHECK(test_v2s.IsLaneSizeS());
  CHECK(!test_v2s.IsLaneSizeD());
  CHECK_EQ(test_v2s.LaneSizeInBits(), 32U);

  VRegister test_v4s(VRegister::VRegFromCode(31).V4S());
  CHECK_EQ(test_v4s.code(), 31);
  CHECK_EQ(test_v4s.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v4s.IsLaneSizeB());
  CHECK(!test_v4s.IsLaneSizeH());
  CHECK(test_v4s.IsLaneSizeS());
  CHECK(!test_v4s.IsLaneSizeD());
  CHECK_EQ(test_v4s.LaneSizeInBits(), 32U);

  VRegister test_v1d(VRegister::VRegFromCode(31).V1D());
  CHECK_EQ(test_v1d.code(), 31);
  CHECK_EQ(test_v1d.SizeInBits(), kDRegSizeInBits);
  CHECK(!test_v1d.IsLaneSizeB());
  CHECK(!test_v1d.IsLaneSizeH());
  CHECK(!test_v1d.IsLaneSizeS());
  CHECK(test_v1d.IsLaneSizeD());
  CHECK_EQ(test_v1d.LaneSizeInBits(), 64U);

  VRegister test_v2d(VRegister::VRegFromCode(31).V2D());
  CHECK_EQ(test_v2d.code(), 31);
  CHECK_EQ(test_v2d.SizeInBits(), kQRegSizeInBits);
  CHECK(!test_v2d.IsLaneSizeB());
  CHECK(!test_v2d.IsLaneSizeH());
  CHECK(!test_v2d.IsLaneSizeS());
  CHECK(test_v2d.IsLaneSizeD());
  CHECK_EQ(test_v2d.LaneSizeInBits(), 64U);

  CHECK(test_v1d.IsSameFormat(test_v1d));
  CHECK(test_v2d.IsSameFormat(test_v2d));
  CHECK(!test_v1d.IsSameFormat(test_v2d));
  CHECK(!test_v2s.IsSameFormat(test_v2d));
}

TEST(isvalid) {
  // This test doesn't generate any code, but it verifies some invariants
  // related to IsValid().
  CHECK(!NoReg.is_valid());
  CHECK(!NoVReg.is_valid());
  CHECK(!NoCPUReg.is_valid());

  CHECK(x0.is_valid());
  CHECK(w0.is_valid());
  CHECK(x30.is_valid());
  CHECK(w30.is_valid());
  CHECK(xzr.is_valid());
  CHECK(wzr.is_valid());

  CHECK(sp.is_valid());
  CHECK(wsp.is_valid());

  CHECK(d0.is_valid());
  CHECK(s0.is_valid());
  CHECK(d31.is_valid());
  CHECK(s31.is_valid());

  CHECK(x0.IsRegister());
  CHECK(w0.IsRegister());
  CHECK(xzr.IsRegister());
  CHECK(wzr.IsRegister());
  CHECK(sp.IsRegister());
  CHECK(wsp.IsRegister());
  CHECK(!x0.IsVRegister());
  CHECK(!w0.IsVRegister());
  CHECK(!xzr.IsVRegister());
  CHECK(!wzr.IsVRegister());
  CHECK(!sp.IsVRegister());
  CHECK(!wsp.IsVRegister());

  CHECK(d0.IsVRegister());
  CHECK(s0.IsVRegister());
  CHECK(!d0.IsRegister());
  CHECK(!s0.IsRegister());

  // Test the same as before, but using CPURegister types. This shouldn't make
  // any difference.
  CHECK(static_cast<CPURegister>(x0).is_valid());
  CHECK(static_cast<CPURegister>(w0).is_valid());
  CHECK(static_cast<CPURegister>(x30).is_valid());
  CHECK(static_cast<CPURegister>(w30).is_valid());
  CHECK(static_cast<CPURegister>(xzr).is_valid());
  CHECK(static_cast<CPURegister>(wzr).is_valid());

  CHECK(static_cast<CPURegister>(sp).is_valid());
  CHECK(static_cast<CPURegister>(wsp).is_valid());

  CHECK(static_cast<CPURegister>(d0).is_valid());
  CHECK(static_cast<CPURegister>(s0).is_valid());
  CHECK(static_cast<CPURegister>(d31).is_valid());
  CHECK(static_cast<CPURegister>(s31).is_valid());

  CHECK(static_cast<CPURegister>(x0).IsRegister());
  CHECK(static_cast<CPURegister>(w0).IsRegister());
  CHECK(static_cast<CPURegister>(xzr).IsRegister());
  CHECK(static_cast<CPURegister>(wzr).IsRegister());
  CHECK(static_cast<CPURegister>(sp).IsRegister());
  CHECK(static_cast<CPURegister>(wsp).IsRegister());
  CHECK(!static_cast<CPURegister>(x0).IsVRegister());
  CHECK(!static_cast<CPURegister>(w0).IsVRegister());
  CHECK(!static_cast<CPURegister>(xzr).IsVRegister());
  CHECK(!static_cast<CPURegister>(wzr).IsVRegister());
  CHECK(!static_cast<CPURegister>(sp).IsVRegister());
  CHECK(!static_cast<CPURegister>(wsp).IsVRegister());

  CHECK(static_cast<CPURegister>(d0).IsVRegister());
  CHECK(static_cast<CPURegister>(s0).IsVRegister());
  CHECK(!static_cast<CPURegister>(d0).IsRegister());
  CHECK(!static_cast<CPURegister>(s0).IsRegister());
}

TEST(areconsecutive) {
  // This test generates no code; it just checks that AreConsecutive works.
  CHECK(AreConsecutive(b0, NoVReg));
  CHECK(AreConsecutive(b1, b2));
  CHECK(AreConsecutive(b3, b4, b5));
  CHECK(AreConsecutive(b6, b7, b8, b9));
  CHECK(AreConsecutive(h10, NoVReg));
  CHECK(AreConsecutive(h11, h12));
  CHECK(AreConsecutive(h13, h14, h15));
  CHECK(AreConsecutive(h16, h17, h18, h19));
  CHECK(AreConsecutive(s20, NoVReg));
  CHECK(AreConsecutive(s21, s22));
  CHECK(AreConsecutive(s23, s24, s25));
  CHECK(AreConsecutive(s26, s27, s28, s29));
  CHECK(AreConsecutive(d30, NoVReg));
  CHECK(AreConsecutive(d31, d0));
  CHECK(AreConsecutive(d1, d2, d3));
  CHECK(AreConsecutive(d4, d5, d6, d7));
  CHECK(AreConsecutive(q8, NoVReg));
  CHECK(AreConsecutive(q9, q10));
  CHECK(AreConsecutive(q11, q12, q13));
  CHECK(AreConsecutive(q14, q15, q16, q17));
  CHECK(AreConsecutive(v18, NoVReg));
  CHECK(AreConsecutive(v19, v20));
  CHECK(AreConsecutive(v21, v22, v23));
  CHECK(AreConsecutive(v24, v25, v26, v27));
  CHECK(AreConsecutive(b29, h30));
  CHECK(AreConsecutive(s31, d0, q1));
  CHECK(AreConsecutive(v2, b3, h4, s5));

  CHECK(AreConsecutive(b26, b27, NoVReg, NoVReg));
  CHECK(AreConsecutive(h28, NoVReg, NoVReg, NoVReg));

  CHECK(!AreConsecutive(b0, b2));
  CHECK(!AreConsecutive(h1, h0));
  CHECK(!AreConsecutive(s31, s1));
  CHECK(!AreConsecutive(d12, d12));
  CHECK(!AreConsecutive(q31, q1));

  CHECK(!AreConsecutive(b5, b4, b3));
  CHECK(!AreConsecutive(h15, h16, h15, h14));
  CHECK(!AreConsecutive(s25, s24, s23, s22));
  CHECK(!AreConsecutive(d5, d6, d7, d6));
  CHECK(!AreConsecutive(q15, q16, q17, q6));

  CHECK(!AreConsecutive(b0, b1, b3));
  CHECK(!AreConsecutive(h4, h5, h6, h6));
  CHECK(!AreConsecutive(d15, d16, d18, NoVReg));
  CHECK(!AreConsecutive(s28, s30, NoVReg, NoVReg));
}

TEST(cpureglist_utils_x) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of X registers.
  CPURegList test(x0, x1, x2, x3);

  CHECK(test.IncludesAliasOf(x0));
  CHECK(test.IncludesAliasOf(x1));
  CHECK(test.IncludesAliasOf(x2));
  CHECK(test.IncludesAliasOf(x3));
  CHECK(test.IncludesAliasOf(w0));
  CHECK(test.IncludesAliasOf(w1));
  CHECK(test.IncludesAliasOf(w2));
  CHECK(test.IncludesAliasOf(w3));

  CHECK(!test.IncludesAliasOf(x4));
  CHECK(!test.IncludesAliasOf(x30));
  CHECK(!test.IncludesAliasOf(xzr));
  CHECK(!test.IncludesAliasOf(sp));
  CHECK(!test.IncludesAliasOf(w4));
  CHECK(!test.IncludesAliasOf(w30));
  CHECK(!test.IncludesAliasOf(wzr));
  CHECK(!test.IncludesAliasOf(wsp));

  CHECK(!test.IncludesAliasOf(d0));
  CHECK(!test.IncludesAliasOf(d1));
  CHECK(!test.IncludesAliasOf(d2));
  CHECK(!test.IncludesAliasOf(d3));
  CHECK(!test.IncludesAliasOf(s0));
  CHECK(!test.IncludesAliasOf(s1));
  CHECK(!test.IncludesAliasOf(s2));
  CHECK(!test.IncludesAliasOf(s3));

  CHECK(!test.IsEmpty());

  CHECK_EQ(test.type(), x0.type());

  CHECK_EQ(test.PopHighestIndex(), x3);
  CHECK_EQ(test.PopLowestIndex(), x0);

  CHECK(test.IncludesAliasOf(x1));
  CHECK(test.IncludesAliasOf(x2));
  CHECK(test.IncludesAliasOf(w1));
  CHECK(test.IncludesAliasOf(w2));
  CHECK(!test.IncludesAliasOf(x0));
  CHECK(!test.IncludesAliasOf(x3));
  CHECK(!test.IncludesAliasOf(w0));
  CHECK(!test.IncludesAliasOf(w3));

  CHECK_EQ(test.PopHighestIndex(), x2);
  CHECK_EQ(test.PopLowestIndex(), x1);

  CHECK(!test.IncludesAliasOf(x1));
  CHECK(!test.IncludesAliasOf(x2));
  CHECK(!test.IncludesAliasOf(w1));
  CHECK(!test.IncludesAliasOf(w2));

  CHECK(test.IsEmpty());
}

TEST(cpureglist_utils_w) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of W registers.
  CPURegList test(w10, w11, w12, w13);

  CHECK(test.IncludesAliasOf(x10));
  CHECK(test.IncludesAliasOf(x11));
  CHECK(test.IncludesAliasOf(x12));
  CHECK(test.IncludesAliasOf(x13));
  CHECK(test.IncludesAliasOf(w10));
  CHECK(test.IncludesAliasOf(w11));
  CHECK(test.IncludesAliasOf(w12));
  CHECK(test.IncludesAliasOf(w13));

  CHECK(!test.IncludesAliasOf(x0));
  CHECK(!test.IncludesAliasOf(x9));
  CHECK(!test.IncludesAliasOf(x14));
  CHECK(!test.IncludesAliasOf(x30));
  CHECK(!test.IncludesAliasOf(xzr));
  CHECK(!test.IncludesAliasOf(sp));
  CHECK(!test.IncludesAliasOf(w0));
  CHECK(!test.IncludesAliasOf(w9));
  CHECK(!test.IncludesAliasOf(w14));
  CHECK(!test.IncludesAliasOf(w30));
  CHECK(!test.IncludesAliasOf(wzr));
  CHECK(!test.IncludesAliasOf(wsp));

  CHECK(!test.IncludesAliasOf(d10));
  CHECK(!test.IncludesAliasOf(d11));
  CHECK(!test.IncludesAliasOf(d12));
  CHECK(!test.IncludesAliasOf(d13));
  CHECK(!test.IncludesAliasOf(s10));
  CHECK(!test.IncludesAliasOf(s11));
  CHECK(!test.IncludesAliasOf(s12));
  CHECK(!test.IncludesAliasOf(s13));

  CHECK(!test.IsEmpty());

  CHECK_EQ(test.type(), w10.type());

  CHECK_EQ(test.PopHighestIndex(), w13);
  CHECK_EQ(test.PopLowestIndex(), w10);

  CHECK(test.IncludesAliasOf(x11));
  CHECK(test.IncludesAliasOf(x12));
  CHECK(test.IncludesAliasOf(w11));
  CHECK(test.IncludesAliasOf(w12));
  CHECK(!test.IncludesAliasOf(x10));
  CHECK(!test.IncludesAliasOf(x13));
  CHECK(!test.IncludesAliasOf(w10));
  CHECK(!test.IncludesAliasOf(w13));

  CHECK_EQ(test.PopHighestIndex(), w12);
  CHECK_EQ(test.PopLowestIndex(), w11);

  CHECK(!test.IncludesAliasOf(x11));
  CHECK(!test.IncludesAliasOf(x12));
  CHECK(!test.IncludesAliasOf(w11));
  CHECK(!test.IncludesAliasOf(w12));

  CHECK(test.IsEmpty());
}

TEST(cpureglist_utils_d) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of D registers.
  CPURegList test(d20, d21, d22, d23);

  CHECK(test.IncludesAliasOf(d20));
  CHECK(test.IncludesAliasOf(d21));
  CHECK(test.IncludesAliasOf(d22));
  CHECK(test.IncludesAliasOf(d23));
  CHECK(test.IncludesAliasOf(s20));
  CHECK(test.IncludesAliasOf(s21));
  CHECK(test.IncludesAliasOf(s22));
  CHECK(test.IncludesAliasOf(s23));

  CHECK(!test.IncludesAliasOf(d0));
  CHECK(!test.IncludesAliasOf(d19));
  CHECK(!test.IncludesAliasOf(d24));
  CHECK(!test.IncludesAliasOf(d31));
  CHECK(!test.IncludesAliasOf(s0));
  CHECK(!test.IncludesAliasOf(s19));
  CHECK(!test.IncludesAliasOf(s24));
  CHECK(!test.IncludesAliasOf(s31));

  CHECK(!test.IncludesAliasOf(x20));
  CHECK(!test.IncludesAliasOf(x21));
  CHECK(!test.IncludesAliasOf(x22));
  CHECK(!test.IncludesAliasOf(x23));
  CHECK(!test.IncludesAliasOf(w20));
  CHECK(!test.IncludesAliasOf(w21));
  CHECK(!test.IncludesAliasOf(w22));
  CHECK(!test.IncludesAliasOf(w23));

  CHECK(!test.IncludesAliasOf(xzr));
  CHECK(!test.IncludesAliasOf(wzr));
  CHECK(!test.IncludesAliasOf(sp));
  CHECK(!test.IncludesAliasOf(wsp));

  CHECK(!test.IsEmpty());

  CHECK_EQ(test.type(), d20.type());

  CHECK_EQ(test.PopHighestIndex(), d23);
  CHECK_EQ(test.PopLowestIndex(), d20);

  CHECK(test.IncludesAliasOf(d21));
  CHECK(test.IncludesAliasOf(d22));
  CHECK(test.IncludesAliasOf(s21));
  CHECK(test.IncludesAliasOf(s22));
  CHECK(!test.IncludesAliasOf(d20));
  CHECK(!test.IncludesAliasOf(d23));
  CHECK(!test.IncludesAliasOf(s20));
  CHECK(!test.IncludesAliasOf(s23));

  CHECK_EQ(test.PopHighestIndex(), d22);
  CHECK_EQ(test.PopLowestIndex(), d21);

  CHECK(!test.IncludesAliasOf(d21));
  CHECK(!test.IncludesAliasOf(d22));
  CHECK(!test.IncludesAliasOf(s21));
  CHECK(!test.IncludesAliasOf(s22));

  CHECK(test.IsEmpty());
}

TEST(cpureglist_utils_s) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test a list of S registers.
  CPURegList test(s20, s21, s22, s23);

  // The type and size mechanisms are already covered, so here we just test
  // that lists of S registers alias individual D registers.

  CHECK(test.IncludesAliasOf(d20));
  CHECK(test.IncludesAliasOf(d21));
  CHECK(test.IncludesAliasOf(d22));
  CHECK(test.IncludesAliasOf(d23));
  CHECK(test.IncludesAliasOf(s20));
  CHECK(test.IncludesAliasOf(s21));
  CHECK(test.IncludesAliasOf(s22));
  CHECK(test.IncludesAliasOf(s23));
}

TEST(cpureglist_utils_empty) {
  // This test doesn't generate any code, but it verifies the behaviour of
  // the CPURegList utility methods.

  // Test an empty list.
  // Empty lists can have type and size properties. Check that we can create
  // them, and that they are empty.
  CPURegList reg32(kWRegSizeInBits, RegList{});
  CPURegList reg64(kXRegSizeInBits, RegList{});
  CPURegList fpreg32(kSRegSizeInBits, DoubleRegList{});
  CPURegList fpreg64(kDRegSizeInBits, DoubleRegList{});

  CHECK(reg32.IsEmpty());
  CHECK(reg64.IsEmpty());
  CHECK(fpreg32.IsEmpty());
  CHECK(fpreg64.IsEmpty());

  CHECK(reg32.PopLowestIndex().IsNone());
  CHECK(reg64.PopLowestIndex().IsNone());
  CHECK(fpreg32.PopLowestIndex().IsNone());
  CHECK(fpreg64.PopLowestIndex().IsNone());

  CHECK(reg32.PopHighestIndex().IsNone());
  CHECK(reg64.PopHighestIndex().IsNone());
  CHECK(fpreg32.PopHighestIndex().IsNone());
  CHECK(fpreg64.PopHighestIndex().IsNone());

  CHECK(reg32.IsEmpty());
  CHECK(reg64.IsEmpty());
  CHECK(fpreg32.IsEmpty());
  CHECK(fpreg64.IsEmpty());
}

TEST(printf) {
  INIT_V8();
  SETUP_SIZE(BUF_SIZE * 2);
  START();

  char const * test_plain_string = "Printf with no arguments.\n";
  char const * test_substring = "'This is a substring.'";
  RegisterDump before;

  // Initialize x29 to the value of the stack pointer. We will use x29 as a
  // temporary stack pointer later, and initializing it in this way allows the
  // RegisterDump check to pass.
  __ Mov(x29, sp);

  // Test simple integer arguments.
  __ Mov(x0, 1234);
  __ Mov(x1, 0x1234);

  // Test simple floating-point arguments.
  __ Fmov(d0, 1.234);

  // Test pointer (string) arguments.
  __ Mov(x2, reinterpret_cast<uintptr_t>(test_substring));

  // Test the maximum number of arguments, and sign extension.
  __ Mov(w3, 0xFFFFFFFF);
  __ Mov(w4, 0xFFFFFFFF);
  __ Mov(x5, 0xFFFFFFFFFFFFFFFF);
  __ Mov(x6, 0xFFFFFFFFFFFFFFFF);
  __ Fmov(s1, 1.234);
  __ Fmov(s2, 2.345);
  __ Fmov(d3, 3.456);
  __ Fmov(d4, 4.567);

  // Test printing callee-saved registers.
  __ Mov(x28, 0x123456789ABCDEF);
  __ Fmov(d10, 42.0);

  // Test with three arguments.
  __ Mov(x10, 3);
  __ Mov(x11, 40);
  __ Mov(x12, 500);

  // A single character.
  __ Mov(w13, 'x');

  // Check that we don't clobber any registers.
  before.Dump(&masm);

  __ Printf(test_plain_string);   // NOLINT(runtime/printf)
  __ Printf("x0: %" PRId64 ", x1: 0x%08" PRIx64 "\n", x0, x1);
  __ Printf("w5: %" PRId32 ", x5: %" PRId64"\n", w5, x5);
  __ Printf("d0: %f\n", d0);
  __ Printf("Test %%s: %s\n", x2);
  __ Printf("w3(uint32): %" PRIu32 "\nw4(int32): %" PRId32 "\n"
            "x5(uint64): %" PRIu64 "\nx6(int64): %" PRId64 "\n",
            w3, w4, x5, x6);
  __ Printf("%%f: %f\n%%g: %g\n%%e: %e\n%%E: %E\n", s1, s2, d3, d4);
  __ Printf("0x%" PRIx32 ", 0x%" PRIx64 "\n", w28, x28);
  __ Printf("%g\n", d10);
  __ Printf("%%%%%s%%%c%%\n", x2, w13);

  // Print the stack pointer.
  __ Printf("StackPointer(sp): 0x%016" PRIx64 ", 0x%08" PRIx32 "\n", sp, wsp);

  // Test with three arguments.
  __ Printf("3=%u, 4=%u, 5=%u\n", x10, x11, x12);

  // Mixed argument types.
  __ Printf("w3: %" PRIu32 ", s1: %f, x5: %" PRIu64 ", d3: %f\n",
            w3, s1, x5, d3);
  __ Printf("s1: %f, d3: %f, w3: %" PRId32 ", x5: %" PRId64 "\n",
            s1, d3, w3, x5);

  END();
  RUN();

  // We cannot easily test the output of the Printf sequences, and because
  // Printf preserves all registers by default, we can't look at the number of
  // bytes that were printed. However, the printf_no_preserve test should check
  // that, and here we just test that we didn't clobber any registers.
  CHECK_EQUAL_REGISTERS(before);
}

TEST(printf_no_preserve) {
  INIT_V8();
  SETUP();
  START();

  char const * test_plain_string = "Printf with no arguments.\n";
  char const * test_substring = "'This is a substring.'";

  __ PrintfNoPreserve(test_plain_string);
  __ Mov(x19, x0);

  // Test simple integer arguments.
  __ Mov(x0, 1234);
  __ Mov(x1, 0x1234);
  __ PrintfNoPreserve("x0: %" PRId64", x1: 0x%08" PRIx64 "\n", x0, x1);
  __ Mov(x20, x0);

  // Test simple floating-point arguments.
  __ Fmov(d0, 1.234);
  __ PrintfNoPreserve("d0: %f\n", d0);
  __ Mov(x21, x0);

  // Test pointer (string) arguments.
  __ Mov(x2, reinterpret_cast<uintptr_t>(test_substring));
  __ PrintfNoPreserve("Test %%s: %s\n", x2);
  __ Mov(x22, x0);

  // Test the maximum number of arguments, and sign extension.
  __ Mov(w3, 0xFFFFFFFF);
  __ Mov(w4, 0xFFFFFFFF);
  __ Mov(x5, 0xFFFFFFFFFFFFFFFF);
  __ Mov(x6, 0xFFFFFFFFFFFFFFFF);
  __ PrintfNoPreserve("w3(uint32): %" PRIu32 "\nw4(int32): %" PRId32 "\n"
                      "x5(uint64): %" PRIu64 "\nx6(int64): %" PRId64 "\n",
                      w3, w4, x5, x6);
  __ Mov(x23, x0);

  __ Fmov(s1, 1.234);
  __ Fmov(s2, 2.345);
  __ Fmov(d3, 3.456);
  __ Fmov(d4, 4.567);
  __ PrintfNoPreserve("%%f: %f\n%%g: %g\n%%e: %e\n%%E: %E\n", s1, s2, d3, d4);
  __ Mov(x24, x0);

  // Test printing callee-saved registers.
  __ Mov(x28, 0x123456789ABCDEF);
  __ PrintfNoPreserve("0x%" PRIx32 ", 0x%" PRIx64 "\n", w28, x28);
  __ Mov(x25, x0);

  __ Fmov(d10, 42.0);
  __ PrintfNoPreserve("%g\n", d10);
  __ Mov(x26, x0);

  // Test with three arguments.
  __ Mov(x3, 3);
  __ Mov(x4, 40);
  __ Mov(x5, 500);
  __ PrintfNoPreserve("3=%u, 4=%u, 5=%u\n", x3, x4, x5);
  __ Mov(x27, x0);

  // Mixed argument types.
  __ Mov(w3, 0xFFFFFFFF);
  __ Fmov(s1, 1.234);
  __ Mov(x5, 0xFFFFFFFFFFFFFFFF);
  __ Fmov(d3, 3.456);
  __ PrintfNoPreserve("w3: %" PRIu32 ", s1: %f, x5: %" PRIu64 ", d3: %f\n",
                      w3, s1, x5, d3);
  __ Mov(x28, x0);

  END();
  RUN();

  // We cannot easily test the exact output of the Printf sequences, but we can
  // use the return code to check that the string length was correct.

  // Printf with no arguments.
  CHECK_EQUAL_64(strlen(test_plain_string), x19);
  // x0: 1234, x1: 0x00001234
  CHECK_EQUAL_64(25, x20);
  // d0: 1.234000
  CHECK_EQUAL_64(13, x21);
  // Test %s: 'This is a substring.'
  CHECK_EQUAL_64(32, x22);
  // w3(uint32): 4294967295
  // w4(int32): -1
  // x5(uint64): 18446744073709551615
  // x6(int64): -1
  CHECK_EQUAL_64(23 + 14 + 33 + 14, x23);
  // %f: 1.234000
  // %g: 2.345
  // %e: 3.456000e+00
  // %E: 4.567000E+00
  CHECK_EQUAL_64(13 + 10 + 17 + 17, x24);
  // 0x89ABCDEF, 0x123456789ABCDEF
  CHECK_EQUAL_64(30, x25);
  // 42
  CHECK_EQUAL_64(3, x26);
  // 3=3, 4=40, 5=500
  CHECK_EQUAL_64(17, x27);
  // w3: 4294967295, s1: 1.234000, x5: 18446744073709551615, d3: 3.456000
  CHECK_EQUAL_64(69, x28);
}

TEST(blr_lr) {
  // A simple test to check that the simulator correcty handle "blr lr".
  INIT_V8();
  SETUP();

  START();
  Label target;
  Label end;

  __ Mov(x0, 0x0);
  __ Adr(lr, &target);

  __ Blr(lr);
  __ Mov(x0, 0xDEADBEEF);
  __ B(&end);

  __ Bind(&target, BranchTargetIdentifier::kBtiCall);
  __ Mov(x0, 0xC001C0DE);

  __ Bind(&end);
  END();

  RUN();

  CHECK_EQUAL_64(0xC001C0DE, x0);
}

TEST(barriers) {
  // Generate all supported barriers, this is just a smoke test
  INIT_V8();
  SETUP();

  START();

  // DMB
  __ Dmb(FullSystem, BarrierAll);
  __ Dmb(FullSystem, BarrierReads);
  __ Dmb(FullSystem, BarrierWrites);
  __ Dmb(FullSystem, BarrierOther);

  __ Dmb(InnerShareable, BarrierAll);
  __ Dmb(InnerShareable, BarrierReads);
  __ Dmb(InnerShareable, BarrierWrites);
  __ Dmb(InnerShareable, BarrierOther);

  __ Dmb(NonShareable, BarrierAll);
  __ Dmb(NonShareable, BarrierReads);
  __ Dmb(NonShareable, BarrierWrites);
  __ Dmb(NonShareable, BarrierOther);

  __ Dmb(OuterShareable, BarrierAll);
  __ Dmb(OuterShareable, BarrierReads);
  __ Dmb(OuterShareable, BarrierWrites);
  __ Dmb(OuterShareable, BarrierOther);

  // DSB
  __ Dsb(FullSystem, BarrierAll);
  __ Dsb(FullSystem, BarrierReads);
  __ Dsb(FullSystem, BarrierWrites);
  __ Dsb(FullSystem, BarrierOther);

  __ Dsb(InnerShareable, BarrierAll);
  __ Dsb(InnerShareable, BarrierReads);
  __ Dsb(InnerShareable, BarrierWrites);
  __ Dsb(InnerShareable, BarrierOther);

  __ Dsb(NonShareable, BarrierAll);
  __ Dsb(NonShareable, BarrierReads);
  __ Dsb(NonShareable, BarrierWrites);
  __ Dsb(NonShareable, BarrierOther);

  __ Dsb(OuterShareable, BarrierAll);
  __ Dsb(OuterShareable, BarrierReads);
  __ Dsb(OuterShareable, BarrierWrites);
  __ Dsb(OuterShareable, BarrierOther);

  // ISB
  __ Isb();

  END();

  RUN();
}

TEST(cas_casa_casl_casal_w) {
  uint64_t data1 = 0x0123456789abcdef;
  uint64_t data2 = 0x0123456789abcdef;
  uint64_t data3 = 0x0123456789abcdef;
  uint64_t data4 = 0x0123456789abcdef;
  uint64_t data5 = 0x0123456789abcdef;
  uint64_t data6 = 0x0123456789abcdef;
  uint64_t data7 = 0x0123456789abcdef;
  uint64_t data8 = 0x0123456789abcdef;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3) + 4);
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4) + 4);
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5) + 0);
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6) + 0);
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7) + 4);
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8) + 4);

  __ Mov(x0, 0xffffffff);

  __ Mov(x1, 0xfedcba9876543210);
  __ Mov(x2, 0x0123456789abcdef);
  __ Mov(x3, 0xfedcba9876543210);
  __ Mov(x4, 0x89abcdef01234567);
  __ Mov(x5, 0xfedcba9876543210);
  __ Mov(x6, 0x0123456789abcdef);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0x89abcdef01234567);

  __ Cas(w1, w0, MemOperand(x21));
  __ Cas(w2, w0, MemOperand(x22));
  __ Casa(w3, w0, MemOperand(x23));
  __ Casa(w4, w0, MemOperand(x24));
  __ Casl(w5, w0, MemOperand(x25));
  __ Casl(w6, w0, MemOperand(x26));
  __ Casal(w7, w0, MemOperand(x27));
  __ Casal(w8, w0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x89abcdef, x1);
    CHECK_EQUAL_64(0x89abcdef, x2);
    CHECK_EQUAL_64(0x01234567, x3);
    CHECK_EQUAL_64(0x01234567, x4);
    CHECK_EQUAL_64(0x89abcdef, x5);
    CHECK_EQUAL_64(0x89abcdef, x6);
    CHECK_EQUAL_64(0x01234567, x7);
    CHECK_EQUAL_64(0x01234567, x8);

    CHECK_EQUAL_64(0x0123456789abcdef, data1);
    CHECK_EQUAL_64(0x01234567ffffffff, data2);
    CHECK_EQUAL_64(0x0123456789abcdef, data3);
    CHECK_EQUAL_64(0xffffffff89abcdef, data4);
    CHECK_EQUAL_64(0x0123456789abcdef, data5);
    CHECK_EQUAL_64(0x01234567ffffffff, data6);
    CHECK_EQUAL_64(0x0123456789abcdef, data7);
    CHECK_EQUAL_64(0xffffffff89abcdef, data8);
  }
}

TEST(cas_casa_casl_casal_x) {
  uint64_t data1 = 0x0123456789abcdef;
  uint64_t data2 = 0x0123456789abcdef;
  uint64_t data3 = 0x0123456789abcdef;
  uint64_t data4 = 0x0123456789abcdef;
  uint64_t data5 = 0x0123456789abcdef;
  uint64_t data6 = 0x0123456789abcdef;
  uint64_t data7 = 0x0123456789abcdef;
  uint64_t data8 = 0x0123456789abcdef;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1));
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2));
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3));
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4));
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5));
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6));
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7));
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8));

  __ Mov(x0, 0xffffffffffffffff);

  __ Mov(x1, 0xfedcba9876543210);
  __ Mov(x2, 0x0123456789abcdef);
  __ Mov(x3, 0xfedcba9876543210);
  __ Mov(x4, 0x0123456789abcdef);
  __ Mov(x5, 0xfedcba9876543210);
  __ Mov(x6, 0x0123456789abcdef);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0x0123456789abcdef);

  __ Cas(x1, x0, MemOperand(x21));
  __ Cas(x2, x0, MemOperand(x22));
  __ Casa(x3, x0, MemOperand(x23));
  __ Casa(x4, x0, MemOperand(x24));
  __ Casl(x5, x0, MemOperand(x25));
  __ Casl(x6, x0, MemOperand(x26));
  __ Casal(x7, x0, MemOperand(x27));
  __ Casal(x8, x0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x0123456789abcdef, x1);
    CHECK_EQUAL_64(0x0123456789abcdef, x2);
    CHECK_EQUAL_64(0x0123456789abcdef, x3);
    CHECK_EQUAL_64(0x0123456789abcdef, x4);
    CHECK_EQUAL_64(0x0123456789abcdef, x5);
    CHECK_EQUAL_64(0x0123456789abcdef, x6);
    CHECK_EQUAL_64(0x0123456789abcdef, x7);
    CHECK_EQUAL_64(0x0123456789abcdef, x8);

    CHECK_EQUAL_64(0x0123456789abcdef, data1);
    CHECK_EQUAL_64(0xffffffffffffffff, data2);
    CHECK_EQUAL_64(0x0123456789abcdef, data3);
    CHECK_EQUAL_64(0xffffffffffffffff, data4);
    CHECK_EQUAL_64(0x0123456789abcdef, data5);
    CHECK_EQUAL_64(0xffffffffffffffff, data6);
    CHECK_EQUAL_64(0x0123456789abcdef, data7);
    CHECK_EQUAL_64(0xffffffffffffffff, data8);
  }
}

TEST(casb_casab_caslb_casalb) {
  uint32_t data1 = 0x01234567;
  uint32_t data2 = 0x01234567;
  uint32_t data3 = 0x01234567;
  uint32_t data4 = 0x01234567;
  uint32_t data5 = 0x01234567;
  uint32_t data6 = 0x01234567;
  uint32_t data7 = 0x01234567;
  uint32_t data8 = 0x01234567;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3) + 1);
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4) + 1);
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5) + 2);
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6) + 2);
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7) + 3);
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8) + 3);

  __ Mov(x0, 0xff);

  __ Mov(x1, 0x76543210);
  __ Mov(x2, 0x01234567);
  __ Mov(x3, 0x76543210);
  __ Mov(x4, 0x67012345);
  __ Mov(x5, 0x76543210);
  __ Mov(x6, 0x45670123);
  __ Mov(x7, 0x76543210);
  __ Mov(x8, 0x23456701);

  __ Casb(w1, w0, MemOperand(x21));
  __ Casb(w2, w0, MemOperand(x22));
  __ Casab(w3, w0, MemOperand(x23));
  __ Casab(w4, w0, MemOperand(x24));
  __ Caslb(w5, w0, MemOperand(x25));
  __ Caslb(w6, w0, MemOperand(x26));
  __ Casalb(w7, w0, MemOperand(x27));
  __ Casalb(w8, w0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x00000067, x1);
    CHECK_EQUAL_64(0x00000067, x2);
    CHECK_EQUAL_64(0x00000045, x3);
    CHECK_EQUAL_64(0x00000045, x4);
    CHECK_EQUAL_64(0x00000023, x5);
    CHECK_EQUAL_64(0x00000023, x6);
    CHECK_EQUAL_64(0x00000001, x7);
    CHECK_EQUAL_64(0x00000001, x8);

    CHECK_EQUAL_64(0x01234567, data1);
    CHECK_EQUAL_64(0x012345ff, data2);
    CHECK_EQUAL_64(0x01234567, data3);
    CHECK_EQUAL_64(0x0123ff67, data4);
    CHECK_EQUAL_64(0x01234567, data5);
    CHECK_EQUAL_64(0x01ff4567, data6);
    CHECK_EQUAL_64(0x01234567, data7);
    CHECK_EQUAL_64(0xff234567, data8);
  }
}

TEST(cash_casah_caslh_casalh) {
  uint64_t data1 = 0x0123456789abcdef;
  uint64_t data2 = 0x0123456789abcdef;
  uint64_t data3 = 0x0123456789abcdef;
  uint64_t data4 = 0x0123456789abcdef;
  uint64_t data5 = 0x0123456789abcdef;
  uint64_t data6 = 0x0123456789abcdef;
  uint64_t data7 = 0x0123456789abcdef;
  uint64_t data8 = 0x0123456789abcdef;

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(&data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(&data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(&data3) + 2);
  __ Mov(x24, reinterpret_cast<uintptr_t>(&data4) + 2);
  __ Mov(x25, reinterpret_cast<uintptr_t>(&data5) + 4);
  __ Mov(x26, reinterpret_cast<uintptr_t>(&data6) + 4);
  __ Mov(x27, reinterpret_cast<uintptr_t>(&data7) + 6);
  __ Mov(x28, reinterpret_cast<uintptr_t>(&data8) + 6);

  __ Mov(x0, 0xffff);

  __ Mov(x1, 0xfedcba9876543210);
  __ Mov(x2, 0x0123456789abcdef);
  __ Mov(x3, 0xfedcba9876543210);
  __ Mov(x4, 0xcdef0123456789ab);
  __ Mov(x5, 0xfedcba9876543210);
  __ Mov(x6, 0x89abcdef01234567);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0x456789abcdef0123);

  __ Cash(w1, w0, MemOperand(x21));
  __ Cash(w2, w0, MemOperand(x22));
  __ Casah(w3, w0, MemOperand(x23));
  __ Casah(w4, w0, MemOperand(x24));
  __ Caslh(w5, w0, MemOperand(x25));
  __ Caslh(w6, w0, MemOperand(x26));
  __ Casalh(w7, w0, MemOperand(x27));
  __ Casalh(w8, w0, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x0000cdef, x1);
    CHECK_EQUAL_64(0x0000cdef, x2);
    CHECK_EQUAL_64(0x000089ab, x3);
    CHECK_EQUAL_64(0x000089ab, x4);
    CHECK_EQUAL_64(0x00004567, x5);
    CHECK_EQUAL_64(0x00004567, x6);
    CHECK_EQUAL_64(0x00000123, x7);
    CHECK_EQUAL_64(0x00000123, x8);

    CHECK_EQUAL_64(0x0123456789abcdef, data1);
    CHECK_EQUAL_64(0x0123456789abffff, data2);
    CHECK_EQUAL_64(0x0123456789abcdef, data3);
    CHECK_EQUAL_64(0x01234567ffffcdef, data4);
    CHECK_EQUAL_64(0x0123456789abcdef, data5);
    CHECK_EQUAL_64(0x0123ffff89abcdef, data6);
    CHECK_EQUAL_64(0x0123456789abcdef, data7);
    CHECK_EQUAL_64(0xffff456789abcdef, data8);
  }
}

TEST(casp_caspa_caspl_caspal_w) {
  uint64_t data1[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data2[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data3[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data4[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data5[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data6[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data7[] = {0x7766554433221100, 0xffeeddccbbaa9988};
  uint64_t data8[] = {0x7766554433221100, 0xffeeddccbbaa9988};

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3) + 8);
  __ Mov(x24, reinterpret_cast<uintptr_t>(data4) + 8);
  __ Mov(x25, reinterpret_cast<uintptr_t>(data5) + 8);
  __ Mov(x26, reinterpret_cast<uintptr_t>(data6) + 8);
  __ Mov(x27, reinterpret_cast<uintptr_t>(data7) + 0);
  __ Mov(x28, reinterpret_cast<uintptr_t>(data8) + 0);

  __ Mov(x0, 0xfff00fff);
  __ Mov(x1, 0xfff11fff);

  __ Mov(x2, 0x77665544);
  __ Mov(x3, 0x33221100);
  __ Mov(x4, 0x33221100);
  __ Mov(x5, 0x77665544);

  __ Mov(x6, 0xffeeddcc);
  __ Mov(x7, 0xbbaa9988);
  __ Mov(x8, 0xbbaa9988);
  __ Mov(x9, 0xffeeddcc);

  __ Mov(x10, 0xffeeddcc);
  __ Mov(x11, 0xbbaa9988);
  __ Mov(x12, 0xbbaa9988);
  __ Mov(x13, 0xffeeddcc);

  __ Mov(x14, 0x77665544);
  __ Mov(x15, 0x33221100);
  __ Mov(x16, 0x33221100);
  __ Mov(x17, 0x77665544);

  __ Casp(w2, w3, w0, w1, MemOperand(x21));
  __ Casp(w4, w5, w0, w1, MemOperand(x22));
  __ Caspa(w6, w7, w0, w1, MemOperand(x23));
  __ Caspa(w8, w9, w0, w1, MemOperand(x24));
  __ Caspl(w10, w11, w0, w1, MemOperand(x25));
  __ Caspl(w12, w13, w0, w1, MemOperand(x26));
  __ Caspal(w14, w15, w0, w1, MemOperand(x27));
  __ Caspal(w16, w17, w0, w1, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x33221100, x2);
    CHECK_EQUAL_64(0x77665544, x3);
    CHECK_EQUAL_64(0x33221100, x4);
    CHECK_EQUAL_64(0x77665544, x5);
    CHECK_EQUAL_64(0xbbaa9988, x6);
    CHECK_EQUAL_64(0xffeeddcc, x7);
    CHECK_EQUAL_64(0xbbaa9988, x8);
    CHECK_EQUAL_64(0xffeeddcc, x9);
    CHECK_EQUAL_64(0xbbaa9988, x10);
    CHECK_EQUAL_64(0xffeeddcc, x11);
    CHECK_EQUAL_64(0xbbaa9988, x12);
    CHECK_EQUAL_64(0xffeeddcc, x13);
    CHECK_EQUAL_64(0x33221100, x14);
    CHECK_EQUAL_64(0x77665544, x15);
    CHECK_EQUAL_64(0x33221100, x16);
    CHECK_EQUAL_64(0x77665544, x17);

    CHECK_EQUAL_64(0x7766554433221100, data1[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data1[1]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data2[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data2[1]);
    CHECK_EQUAL_64(0x7766554433221100, data3[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data3[1]);
    CHECK_EQUAL_64(0x7766554433221100, data4[0]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data4[1]);
    CHECK_EQUAL_64(0x7766554433221100, data5[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data5[1]);
    CHECK_EQUAL_64(0x7766554433221100, data6[0]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data6[1]);
    CHECK_EQUAL_64(0x7766554433221100, data7[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data7[1]);
    CHECK_EQUAL_64(0xfff11ffffff00fff, data8[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data8[1]);
  }
}

TEST(casp_caspa_caspl_caspal_x) {
  alignas(kXRegSize * 2)
      uint64_t data1[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data2[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data3[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data4[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data5[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data6[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data7[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};
  alignas(kXRegSize * 2)
      uint64_t data8[] = {0x7766554433221100, 0xffeeddccbbaa9988,
                          0xfedcba9876543210, 0x0123456789abcdef};

  INIT_V8();
  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x21, reinterpret_cast<uintptr_t>(data1) + 0);
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2) + 0);
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3) + 16);
  __ Mov(x24, reinterpret_cast<uintptr_t>(data4) + 16);
  __ Mov(x25, reinterpret_cast<uintptr_t>(data5) + 16);
  __ Mov(x26, reinterpret_cast<uintptr_t>(data6) + 16);
  __ Mov(x27, reinterpret_cast<uintptr_t>(data7) + 0);
  __ Mov(x28, reinterpret_cast<uintptr_t>(data8) + 0);

  __ Mov(x0, 0xfffffff00fffffff);
  __ Mov(x1, 0xfffffff11fffffff);

  __ Mov(x2, 0xffeeddccbbaa9988);
  __ Mov(x3, 0x7766554433221100);
  __ Mov(x4, 0x7766554433221100);
  __ Mov(x5, 0xffeeddccbbaa9988);

  __ Mov(x6, 0x0123456789abcdef);
  __ Mov(x7, 0xfedcba9876543210);
  __ Mov(x8, 0xfedcba9876543210);
  __ Mov(x9, 0x0123456789abcdef);

  __ Mov(x10, 0x0123456789abcdef);
  __ Mov(x11, 0xfedcba9876543210);
  __ Mov(x12, 0xfedcba9876543210);
  __ Mov(x13, 0x0123456789abcdef);

  __ Mov(x14, 0xffeeddccbbaa9988);
  __ Mov(x15, 0x7766554433221100);
  __ Mov(x16, 0x7766554433221100);
  __ Mov(x17, 0xffeeddccbbaa9988);

  __ Casp(x2, x3, x0, x1, MemOperand(x21));
  __ Casp(x4, x5, x0, x1, MemOperand(x22));
  __ Caspa(x6, x7, x0, x1, MemOperand(x23));
  __ Caspa(x8, x9, x0, x1, MemOperand(x24));
  __ Caspl(x10, x11, x0, x1, MemOperand(x25));
  __ Caspl(x12, x13, x0, x1, MemOperand(x26));
  __ Caspal(x14, x15, x0, x1, MemOperand(x27));
  __ Caspal(x16, x17, x0, x1, MemOperand(x28));

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(0x7766554433221100, x2);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x3);
    CHECK_EQUAL_64(0x7766554433221100, x4);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x5);

    CHECK_EQUAL_64(0xfedcba9876543210, x6);
    CHECK_EQUAL_64(0x0123456789abcdef, x7);
    CHECK_EQUAL_64(0xfedcba9876543210, x8);
    CHECK_EQUAL_64(0x0123456789abcdef, x9);

    CHECK_EQUAL_64(0xfedcba9876543210, x10);
    CHECK_EQUAL_64(0x0123456789abcdef, x11);
    CHECK_EQUAL_64(0xfedcba9876543210, x12);
    CHECK_EQUAL_64(0x0123456789abcdef, x13);

    CHECK_EQUAL_64(0x7766554433221100, x14);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x15);
    CHECK_EQUAL_64(0x7766554433221100, x16);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, x17);

    CHECK_EQUAL_64(0x7766554433221100, data1[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data1[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data1[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data1[3]);

    CHECK_EQUAL_64(0xfffffff00fffffff, data2[0]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data2[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data2[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data2[3]);

    CHECK_EQUAL_64(0x7766554433221100, data3[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data3[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data3[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data3[3]);

    CHECK_EQUAL_64(0x7766554433221100, data4[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data4[1]);
    CHECK_EQUAL_64(0xfffffff00fffffff, data4[2]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data4[3]);

    CHECK_EQUAL_64(0x7766554433221100, data5[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data5[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data5[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data5[3]);

    CHECK_EQUAL_64(0x7766554433221100, data6[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data6[1]);
    CHECK_EQUAL_64(0xfffffff00fffffff, data6[2]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data6[3]);

    CHECK_EQUAL_64(0x7766554433221100, data7[0]);
    CHECK_EQUAL_64(0xffeeddccbbaa9988, data7[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data7[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data7[3]);

    CHECK_EQUAL_64(0xfffffff00fffffff, data8[0]);
    CHECK_EQUAL_64(0xfffffff11fffffff, data8[1]);
    CHECK_EQUAL_64(0xfedcba9876543210, data8[2]);
    CHECK_EQUAL_64(0x0123456789abcdef, data8[3]);
  }
}

typedef void (MacroAssembler::*AtomicMemoryLoadSignature)(
    const Register& rs, const Register& rt, const MemOperand& src);
typedef void (MacroAssembler::*AtomicMemoryStoreSignature)(
    const Register& rs, const MemOperand& src);

static void AtomicMemoryWHelper(AtomicMemoryLoadSignature* load_funcs,
                                AtomicMemoryStoreSignature* store_funcs,
                                uint64_t arg1, uint64_t arg2, uint64_t expected,
                                uint64_t result_mask) {
  alignas(kXRegSize * 2) uint64_t data0[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data1[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data2[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data3[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data4[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data5[] = {arg2, 0};

  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x20, reinterpret_cast<uintptr_t>(data0));
  __ Mov(x21, reinterpret_cast<uintptr_t>(data1));
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2));
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3));

  __ Mov(x0, arg1);
  __ Mov(x1, arg1);
  __ Mov(x2, arg1);
  __ Mov(x3, arg1);

  (masm.*(load_funcs[0]))(w0, w10, MemOperand(x20));
  (masm.*(load_funcs[1]))(w1, w11, MemOperand(x21));
  (masm.*(load_funcs[2]))(w2, w12, MemOperand(x22));
  (masm.*(load_funcs[3]))(w3, w13, MemOperand(x23));

  if (store_funcs != NULL) {
    __ Mov(x24, reinterpret_cast<uintptr_t>(data4));
    __ Mov(x25, reinterpret_cast<uintptr_t>(data5));
    __ Mov(x4, arg1);
    __ Mov(x5, arg1);

    (masm.*(store_funcs[0]))(w4, MemOperand(x24));
    (masm.*(store_funcs[1]))(w5, MemOperand(x25));
  }

  END();

  if (CAN_RUN()) {
    RUN();

    uint64_t stored_value = arg2 & result_mask;
    CHECK_EQUAL_64(stored_value, x10);
    CHECK_EQUAL_64(stored_value, x11);
    CHECK_EQUAL_64(stored_value, x12);
    CHECK_EQUAL_64(stored_value, x13);

    // The data fields contain arg2 already then only the bits masked by
    // result_mask are overwritten.
    uint64_t final_expected = (arg2 & ~result_mask) | (expected & result_mask);
    CHECK_EQUAL_64(final_expected, data0[0]);
    CHECK_EQUAL_64(final_expected, data1[0]);
    CHECK_EQUAL_64(final_expected, data2[0]);
    CHECK_EQUAL_64(final_expected, data3[0]);

    if (store_funcs != NULL) {
      CHECK_EQUAL_64(final_expected, data4[0]);
      CHECK_EQUAL_64(final_expected, data5[0]);
    }
  }
}

static void AtomicMemoryXHelper(AtomicMemoryLoadSignature* load_funcs,
                                AtomicMemoryStoreSignature* store_funcs,
                                uint64_t arg1, uint64_t arg2,
                                uint64_t expected) {
  alignas(kXRegSize * 2) uint64_t data0[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data1[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data2[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data3[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data4[] = {arg2, 0};
  alignas(kXRegSize * 2) uint64_t data5[] = {arg2, 0};

  SETUP();
  SETUP_FEATURE(LSE);

  START();

  __ Mov(x20, reinterpret_cast<uintptr_t>(data0));
  __ Mov(x21, reinterpret_cast<uintptr_t>(data1));
  __ Mov(x22, reinterpret_cast<uintptr_t>(data2));
  __ Mov(x23, reinterpret_cast<uintptr_t>(data3));

  __ Mov(x0, arg1);
  __ Mov(x1, arg1);
  __ Mov(x2, arg1);
  __ Mov(x3, arg1);

  (masm.*(load_funcs[0]))(x0, x10, MemOperand(x20));
  (masm.*(load_funcs[1]))(x1, x11, MemOperand(x21));
  (masm.*(load_funcs[2]))(x2, x12, MemOperand(x22));
  (masm.*(load_funcs[3]))(x3, x13, MemOperand(x23));

  if (store_funcs != NULL) {
    __ Mov(x24, reinterpret_cast<uintptr_t>(data4));
    __ Mov(x25, reinterpret_cast<uintptr_t>(data5));
    __ Mov(x4, arg1);
    __ Mov(x5, arg1);

    (masm.*(store_funcs[0]))(x4, MemOperand(x24));
    (masm.*(store_funcs[1]))(x5, MemOperand(x25));
  }

  END();

  if (CAN_RUN()) {
    RUN();

    CHECK_EQUAL_64(arg2, x10);
    CHECK_EQUAL_64(arg2, x11);
    CHECK_EQUAL_64(arg2, x12);
    CHECK_EQUAL_64(arg2, x13);

    CHECK_EQUAL_64(expected, data0[0]);
    CHECK_EQUAL_64(expected, data1[0]);
    CHECK_EQUAL_64(expected, data2[0]);
    CHECK_EQUAL_64(expected, data3[0]);

    if (store_funcs != NULL) {
      CHECK_EQUAL_64(expected, data4[0]);
      CHECK_EQUAL_64(expected, data5[0]);
    }
  }
}

// clang-format off
#define MAKE_LOADS(NAME)           \
    {&MacroAssembler::Ld##NAME,    \
     &MacroAssembler::Ld##NAME##a, \
     &MacroAssembler::Ld##NAME##l, \
     &MacroAssembler::Ld##NAME##al}
#define MAKE_STORES(NAME) \
    {&MacroAssembler::St##NAME, &MacroAssembler::St##NAME##l}

#define MAKE_B_LOADS(NAME)          \
    {&MacroAssembler::Ld##NAME##b,  \
     &MacroAssembler::Ld##NAME##ab, \
     &MacroAssembler::Ld##NAME##lb, \
     &MacroAssembler::Ld##NAME##alb}
#define MAKE_B_STORES(NAME) \
    {&MacroAssembler::St##NAME##b, &MacroAssembler::St##NAME##lb}

#define MAKE_H_LOADS(NAME)          \
    {&MacroAssembler::Ld##NAME##h,  \
     &MacroAssembler::Ld##NAME##ah, \
     &MacroAssembler::Ld##NAME##lh, \
     &MacroAssembler::Ld##NAME##alh}
#define MAKE_H_STORES(NAME) \
    {&MacroAssembler::St##NAME##h, &MacroAssembler::St##NAME##lh}
// clang-format on

TEST(atomic_memory_add) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(add);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(add);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(add);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(add);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(add);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(add);

  // The arguments are chosen to have two useful properties:
  //  * When multiplied by small values (such as a register index), this value
  //    is clearly readable in the result.
  //  * The value is not formed from repeating fixed-size smaller values, so it
  //    can be used to detect endianness-related errors.
  uint64_t arg1 = 0x0100001000100101;
  uint64_t arg2 = 0x0200002000200202;
  uint64_t expected = arg1 + arg2;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_clr) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(clr);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(clr);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(clr);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(clr);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(clr);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(clr);

  uint64_t arg1 = 0x0300003000300303;
  uint64_t arg2 = 0x0500005000500505;
  uint64_t expected = arg2 & ~arg1;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_eor) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(eor);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(eor);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(eor);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(eor);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(eor);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(eor);

  uint64_t arg1 = 0x0300003000300303;
  uint64_t arg2 = 0x0500005000500505;
  uint64_t expected = arg1 ^ arg2;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_set) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(set);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(set);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(set);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(set);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(set);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(set);

  uint64_t arg1 = 0x0300003000300303;
  uint64_t arg2 = 0x0500005000500505;
  uint64_t expected = arg1 | arg2;

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_smax) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(smax);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(smax);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(smax);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(smax);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(smax);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(smax);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x0100001000100101;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_smin) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(smin);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(smin);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(smin);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(smin);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(smin);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(smin);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x8100000080108181;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_umax) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(umax);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(umax);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(umax);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(umax);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(umax);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(umax);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x8100000080108181;

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_umin) {
  AtomicMemoryLoadSignature loads[] = MAKE_LOADS(umin);
  AtomicMemoryStoreSignature stores[] = MAKE_STORES(umin);
  AtomicMemoryLoadSignature b_loads[] = MAKE_B_LOADS(umin);
  AtomicMemoryStoreSignature b_stores[] = MAKE_B_STORES(umin);
  AtomicMemoryLoadSignature h_loads[] = MAKE_H_LOADS(umin);
  AtomicMemoryStoreSignature h_stores[] = MAKE_H_STORES(umin);

  uint64_t arg1 = 0x8100000080108181;
  uint64_t arg2 = 0x0100001000100101;
  uint64_t expected = 0x0100001000100101;

  INIT_V8();

  AtomicMemoryWHelper(b_loads, b_stores, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, h_stores, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, stores, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, stores, arg1, arg2, expected);
}

TEST(atomic_memory_swp) {
  AtomicMemoryLoadSignature loads[] = {
      &MacroAssembler::Swp, &MacroAssembler::Swpa, &MacroAssembler::Swpl,
      &MacroAssembler::Swpal};
  AtomicMemoryLoadSignature b_loads[] = {
      &MacroAssembler::Swpb, &MacroAssembler::Swpab, &MacroAssembler::Swplb,
      &MacroAssembler::Swpalb};
  AtomicMemoryLoadSignature h_loads[] = {
      &MacroAssembler::Swph, &MacroAssembler::Swpah, &MacroAssembler::Swplh,
      &MacroAssembler::Swpalh};

  uint64_t arg1 = 0x0100001000100101;
  uint64_t arg2 = 0x0200002000200202;
  uint64_t expected = 0x0100001000100101;

  INIT_V8();

  // SWP functions have equivalent signatures to the Atomic Memory LD functions
  // so we can use the same helper but without the ST aliases.
  AtomicMemoryWHelper(b_loads, NULL, arg1, arg2, expected, kByteMask);
  AtomicMemoryWHelper(h_loads, NULL, arg1, arg2, expected, kHalfWordMask);
  AtomicMemoryWHelper(loads, NULL, arg1, arg2, expected, kWordMask);
  AtomicMemoryXHelper(loads, NULL, arg1, arg2, expected);
}

TEST(process_nan_double) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  double sn = base::bit_cast<double>(0x7FF5555511111111);
  double qn = base::bit_cast<double>(0x7FFAAAAA11111111);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsQuietNaN(qn));

  // The input NaNs after passing through ProcessNaN.
  double sn_proc = base::bit_cast<double>(0x7FFD555511111111);
  double qn_proc = qn;
  CHECK(IsQuietNaN(sn_proc));
  CHECK(IsQuietNaN(qn_proc));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaN, and check that
  // they all handle the NaN correctly.
  __ Fmov(d0, sn);
  __ Fmov(d10, qn);

  // Operations that always propagate NaNs unchanged, even signalling NaNs.
  //   - Signalling NaN
  __ Fmov(d1, d0);
  __ Fabs(d2, d0);
  __ Fneg(d3, d0);
  //   - Quiet NaN
  __ Fmov(d11, d10);
  __ Fabs(d12, d10);
  __ Fneg(d13, d10);

  // Operations that use ProcessNaN.
  //   - Signalling NaN
  __ Fsqrt(d4, d0);
  __ Frinta(d5, d0);
  __ Frintn(d6, d0);
  __ Frintz(d7, d0);
  //   - Quiet NaN
  __ Fsqrt(d14, d10);
  __ Frinta(d15, d10);
  __ Frintn(d16, d10);
  __ Frintz(d17, d10);

  // The behaviour of fcvt is checked in TEST(fcvt_sd).

  END();
  RUN();

  uint64_t qn_raw = base::bit_cast<uint64_t>(qn);
  uint64_t sn_raw = base::bit_cast<uint64_t>(sn);

  //   - Signalling NaN
  CHECK_EQUAL_FP64(sn, d1);
  CHECK_EQUAL_FP64(base::bit_cast<double>(sn_raw & ~kDSignMask), d2);
  CHECK_EQUAL_FP64(base::bit_cast<double>(sn_raw ^ kDSignMask), d3);
  //   - Quiet NaN
  CHECK_EQUAL_FP64(qn, d11);
  CHECK_EQUAL_FP64(base::bit_cast<double>(qn_raw & ~kDSignMask), d12);
  CHECK_EQUAL_FP64(base::bit_cast<double>(qn_raw ^ kDSignMask), d13);

  //   - Signalling NaN
  CHECK_EQUAL_FP64(sn_proc, d4);
  CHECK_EQUAL_FP64(sn_proc, d5);
  CHECK_EQUAL_FP64(sn_proc, d6);
  CHECK_EQUAL_FP64(sn_proc, d7);
  //   - Quiet NaN
  CHECK_EQUAL_FP64(qn_proc, d14);
  CHECK_EQUAL_FP64(qn_proc, d15);
  CHECK_EQUAL_FP64(qn_proc, d16);
  CHECK_EQUAL_FP64(qn_proc, d17);
}

TEST(process_nan_float) {
  INIT_V8();
  // Make sure that NaN propagation works correctly.
  float sn = base::bit_cast<float>(0x7F951111);
  float qn = base::bit_cast<float>(0x7FEA1111);
  CHECK(IsSignallingNaN(sn));
  CHECK(IsQuietNaN(qn));

  // The input NaNs after passing through ProcessNaN.
  float sn_proc = base::bit_cast<float>(0x7FD51111);
  float qn_proc = qn;
  CHECK(IsQuietNaN(sn_proc));
  CHECK(IsQuietNaN(qn_proc));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaN, and check that
  // they all handle the NaN correctly.
  __ Fmov(s0, sn);
  __ Fmov(s10, qn);

  // Operations that always propagate NaNs unchanged, even signalling NaNs.
  //   - Signalling NaN
  __ Fmov(s1, s0);
  __ Fabs(s2, s0);
  __ Fneg(s3, s0);
  //   - Quiet NaN
  __ Fmov(s11, s10);
  __ Fabs(s12, s10);
  __ Fneg(s13, s10);

  // Operations that use ProcessNaN.
  //   - Signalling NaN
  __ Fsqrt(s4, s0);
  __ Frinta(s5, s0);
  __ Frintn(s6, s0);
  __ Frintz(s7, s0);
  //   - Quiet NaN
  __ Fsqrt(s14, s10);
  __ Frinta(s15, s10);
  __ Frintn(s16, s10);
  __ Frintz(s17, s10);

  // The behaviour of fcvt is checked in TEST(fcvt_sd).

  END();
  RUN();

  uint32_t qn_raw = base::bit_cast<uint32_t>(qn);
  uint32_t sn_raw = base::bit_cast<uint32_t>(sn);
  uint32_t sign_mask = static_cast<uint32_t>(kSSignMask);

  //   - Signalling NaN
  CHECK_EQUAL_FP32(sn, s1);
  CHECK_EQUAL_FP32(base::bit_cast<float>(sn_raw & ~sign_mask), s2);
  CHECK_EQUAL_FP32(base::bit_cast<float>(sn_raw ^ sign_mask), s3);
  //   - Quiet NaN
  CHECK_EQUAL_FP32(qn, s11);
  CHECK_EQUAL_FP32(base::bit_cast<float>(qn_raw & ~sign_mask), s12);
  CHECK_EQUAL_FP32(base::bit_cast<float>(qn_raw ^ sign_mask), s13);

  //   - Signalling NaN
  CHECK_EQUAL_FP32(sn_proc, s4);
  CHECK_EQUAL_FP32(sn_proc, s5);
  CHECK_EQUAL_FP32(sn_proc, s6);
  CHECK_EQUAL_FP32(sn_proc, s7);
  //   - Quiet NaN
  CHECK_EQUAL_FP32(qn_proc, s14);
  CHECK_EQUAL_FP32(qn_proc, s15);
  CHECK_EQUAL_FP32(qn_proc, s16);
  CHECK_EQUAL_FP32(qn_proc, s17);
}


static void ProcessNaNsHelper(double n, double m, double expected) {
  CHECK(std::isnan(n) || std::isnan(m));
  CHECK(std::isnan(expected));

  SETUP();
  START();

  // Execute a number of instructions which all use ProcessNaNs, and check that
  // they all propagate NaNs correctly.
  __ Fmov(d0, n);
  __ Fmov(d1, m);

  __ Fadd(d2, d0, d1);
  __ Fsub(d3, d0, d1);
  __ Fmul(d4, d0, d1);
  __ Fdiv(d5, d0, d1);
  __ Fmax(d6, d0, d1);
  __ Fmin(d7, d0, d1);

  END();
  RUN();

  CHECK_EQUAL_FP64(expected, d2);
  CHECK_EQUAL_FP64(expected, d3);
  CHECK_EQUAL_FP64(expected, d4);
  CHECK_EQUAL_FP64(expected, d5);
  CHECK_EQUAL_FP64(expecte
```