Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/execution/arm64/simulator-arm64.h`. This is part 2 of a 4-part series.

Here's a breakdown of the code's functions:

1. **Instruction Execution Flow Control:** `CheckBType`, `ExecuteInstruction`.
2. **Instruction Visitation:** Defines a mechanism to "visit" and process different instructions using the `VISITOR_LIST` macro.
3. **Register Access (Integer):** Provides methods to read (`reg`, `wreg`, `xreg`) and write (`set_reg`, `set_wreg`, `set_xreg`, including no-log versions) integer registers, including special handling for the zero register and stack pointer.
4. **Register Access (Vector):**  Similar to integer registers, provides methods to read (`vreg`, `breg`, `hreg`, `sreg`, `dreg`, `qreg`) and write (`set_vreg`, `set_breg`, `set_hreg`, `set_sreg`, `set_dreg`, `set_qreg`, including no-log versions) vector registers.
5. **System Register Access:** Provides access to system registers like `nzcv` and `fpcr`.
6. **Debugging Features:** Includes support for breakpoints (`SetBreakpoint`, `ListBreakpoints`, `CheckBreakpoints`), a "next" command (`break_on_next_`, `CheckBreakNext`), and disassembly (`PrintInstructionsAt`).
7. **Register Printing/Logging:** Offers functions to print register values (`PrintRegisters`, `PrintVRegisters`, `PrintSystemRegisters`, and their "written" variants), with control over logging verbosity. It also defines an enum `PrintRegisterFormat` to specify how registers should be printed.
8. **Memory Access Logging:** Includes functions to log memory reads and writes (`LogRead`, `LogWrite`, `LogVRead`, `LogVWrite`).
9. **Pointer Authentication (PAC):** Defines constants and helper functions related to ARMv8.3 pointer authentication features.
10. **Simulation Helpers:** Provides a collection of protected helper functions for simulating various ARM64 instructions. These include:
    - Condition checking (`ConditionPassed`, `ConditionFailed`).
    - Arithmetic and logical operations (`AddSubHelper`, `AddWithCarry`, `AddSubWithCarry`, `LogicalHelper`, `ConditionalCompareHelper`).
    - Load and store operations (`LoadStoreHelper`, `LoadStorePairHelper`, `CompareAndSwapHelper`, `CompareAndSwapPairHelper`, `AtomicMemorySimpleHelper`, `AtomicMemorySwapHelper`, `LoadStoreAddress`, `LoadStoreWriteBack`, `NEONLoadStoreMultiStructHelper`, `NEONLoadStoreSingleStructHelper`).
    - Memory access checking (`CheckMemoryAccess`, `ProbeMemory`).
    - Raw memory read/write (`MemoryRead`, `MemoryWrite`).
    - Shift and extend operations (`ShiftOperand`, `ExtendValue`).
    - Bitfield manipulation (`Extract`, `DataProcessing2Source`, `BitfieldHelper`).
    - Polynomial multiplication (`PolynomialMult`, `PolynomialMult128`, `Lsl128`, `Eor128`).
    - NEON (SIMD) instruction simulation (load, store, compare, arithmetic, multiply).

Given this detailed analysis, I can now formulate a concise summary that captures the essence of the code.
这是 `v8/src/execution/arm64/simulator-arm64.h` 文件的第二部分，主要延续了第一部分关于 ARM64 指令模拟器的功能定义。它专注于以下几个方面：

**1. 指令执行和控制流：**

* **`CheckBType()` 和相关逻辑：**  这部分代码检查分支目标指令 (Branch Target Instruction, BTI) 的类型，确保控制流跳转到正确的指令。如果配置了 BTI 但目标不是 BTI 指令，则会触发错误。
* **`ExecuteInstruction()`：**  这是模拟器执行单条指令的核心函数。它包含以下步骤：
    * 断言指令地址已对齐。
    * 检查 BTI 类型。
    * 重置 BTI 状态。
    * 检查是否设置了断点。
    * **解码指令 (`Decode(pc_)`)**：虽然这部分代码没有直接展示 `Decode` 函数的实现，但它暗示了模拟器需要解码当前程序计数器 (`pc_`) 指向的指令。
    * 递增程序计数器 (`increment_pc()`)。
    * 记录所有被写入的寄存器 (`LogAllWrittenRegisters()`)，用于调试。
    * 再次检查断点 (`CheckBreakpoints()`)。

**2. 指令访问机制：**

* **`DECLARE` 和 `VISITOR_LIST` 宏：**  这是一种常见的设计模式，用于声明一系列以 `Visit` 开头的函数，每个函数对应一种需要模拟的 ARM64 指令。`VISITOR_LIST` 宏很可能在其他地方定义，用于展开并声明所有具体的指令访问函数。
* **`VisitNEON3SameFP()`：** 这是一个针对特定 NEON (SIMD) 指令的访问函数示例，处理具有相同操作数和浮点格式的 NEON 指令。

**3. 寄存器访问（整数和向量）：**

* **`IsZeroRegister()`：**  判断给定的寄存器代码是否代表零寄存器（通常是 `r31`）。
* **`reg()`, `wreg()`, `xreg()`：**  用于读取通用寄存器的值，可以指定读取的位数（32 位或 64 位）。`Reg31Mode` 用于区分 `r31` 是作为通用寄存器还是栈指针。
* **`set_reg()`, `set_wreg()`, `set_xreg()`：**  用于写入通用寄存器的值。这些函数还会记录寄存器的更新（logging）。
* **`set_reg_no_log()`, `set_wreg_no_log()`, `set_xreg_no_log()`：**  与 `set_reg` 系列函数类似，但不记录寄存器的更新。
* **`set_lr()` 和 `set_sp()`：**  用于设置链接寄存器 (LR) 和栈指针寄存器 (SP) 的快捷方式。
* **向量寄存器访问：**
    * **`qreg_t` 结构体：**  表示 128 位 Q 寄存器。
    * **`vreg()`：**  用于读取向量寄存器的值，可以指定读取的数据类型和大小。
    * **`breg()`, `hreg()`, `sreg()`, `dreg()`, `qreg()`：**  提供更方便的访问不同大小向量寄存器的函数。
    * **`set_vreg()`：**  用于写入向量寄存器的值，可以选择是否记录更新。
    * **`set_vreg_no_log()`：**  写入向量寄存器但不记录更新。

**4. 系统寄存器访问：**

* **`nzcv()`：**  返回表示 NZCV 标志位的系统寄存器的引用（负数、零、进位、溢出）。
* **`fpcr()`：**  返回表示浮点控制寄存器的引用。
* **`RMode()` 和 `DN()`：**  访问浮点控制寄存器的特定位。

**5. 调试辅助功能：**

* **`Breakpoint` 结构体和相关函数 (`SetBreakpoint`, `ListBreakpoints`, `CheckBreakpoints`)：**  用于设置、列出和检查模拟器中的断点。
* **`break_on_next_` 和 `CheckBreakNext()`：**  用于支持 "next" 命令，在执行到下一个 BL (Branch with Link) 指令后暂停。
* **`PrintInstructionsAt()`：**  反汇编指定地址的指令。
* **`PrintRegisters()`, `PrintVRegisters()`, `PrintSystemRegisters()`：**  打印所有寄存器的值。
* **`PrintWrittenRegisters()`, `PrintWrittenVRegisters()`：**  只打印已更新的寄存器的值。
* **`LogWrittenRegisters()`, `LogWrittenVRegisters()`, `LogAllWrittenRegisters()`：**  根据日志参数打印已更新的寄存器。
* **`PrintRegisterFormat` 枚举：**  定义了打印寄存器值的不同格式（例如，作为标量、向量，以及元素的大小）。
* **`GetPrintRegLaneSizeInBytesLog2()`, `GetPrintRegLaneSizeInBytes()`, `GetPrintRegSizeInBytesLog2()`, `GetPrintRegSizeInBytes()`, `GetPrintRegLaneCount()`：**  用于解析 `PrintRegisterFormat`，获取寄存器和元素大小等信息。
* **`GetPrintRegisterFormat()` 系列函数：**  根据数据类型或 `VectorFormat` 获取合适的 `PrintRegisterFormat`。
* **`PrintRegister()`, `PrintVRegister()`, `PrintSystemRegister()`：**  打印单个寄存器的值。
* **`LogRegister()`, `LogVRegister()`, `LogSystemRegister()`：**  根据日志参数打印单个寄存器的值。
* **内存访问打印和日志 (`PrintRead`, `PrintWrite`, `PrintVRead`, `PrintVWrite`, `LogRead`, `LogWrite`, `LogVRead`, `LogVWrite`)**
* **`log_parameters_` 和相关函数：**  用于控制模拟器的日志输出级别。

**6. 指针认证 (PAC) 支持：**

* **`PointerType` 枚举：**  区分数据指针和指令指针。
* **`PACKey` 结构体：**  表示 PAC 密钥。
* **`kPACKeyIB` 常量：**  一个预定义的 PAC 密钥。
* **`HasTBI()`, `GetBottomPACBit()`, `GetTopPACBit()`：**  与指针标记和地址空间布局相关的辅助函数。
* **`CalculatePACMask()`, `ComputePAC()`, `AuthPAC()`, `AddPAC()`, `StripPAC()`：**  用于计算、认证和操作指针认证码的函数。

**7. 受保护的模拟辅助函数：**

* **`ConditionPassed()` 和 `ConditionFailed()`：**  检查条件码是否满足。
* **模板化的算术和逻辑运算辅助函数 (`AddSubHelper`, `AddWithCarry`, `AddSubWithCarry`, `LogicalHelper`, `ConditionalCompareHelper`)**
* **`LoadStoreHelper()` 和 `LoadStorePairHelper()`：**  处理加载和存储指令。
* **模板化的原子操作辅助函数 (`CompareAndSwapHelper`, `CompareAndSwapPairHelper`, `AtomicMemorySimpleHelper`, `AtomicMemorySwapHelper`)**
* **`LoadStoreAddress()`：**  计算加载/存储指令的有效地址。
* **`LoadStoreWriteBack()`：**  处理加载/存储指令的写回操作。
* **NEON 加载/存储多结构体和单结构体辅助函数 (`NEONLoadStoreMultiStructHelper`, `NEONLoadStoreSingleStructHelper`)**
* **`CheckMemoryAccess()`：**  检查内存访问是否有效。
* **`ProbeMemory()`：**  探测内存地址是否可访问。
* **模板化的内存读写函数 (`MemoryRead`, `MemoryWrite`)**
* **模板化的移位和扩展函数 (`ShiftOperand`, `ExtendValue`)**
* **模板化的数据处理函数 (`Extract`, `DataProcessing2Source`, `BitfieldHelper`)**
* **多项式乘法函数 (`PolynomialMult`, `PolynomialMult128`, `Lsl128`, `Eor128`)**
* **大量的 NEON 指令模拟函数 (`ld1`, `ld2`, `ld3`, `ld4`, `st1`, `st2`, `st3`, `st4`, `cmp`, `cmptst`, `add`, `addp`, `mla`, `mls`, `mul`, `fmul`, `fmla`, `fmls`, `fmulx`, `smull`, `umull`, `smlal`, `umlal`, `smlsl`, `umlsl`, `sqdmull`, `sqdmlal`, `sqdmlsl`, `sqdmulh`, `sqrdmulh`)** - 这表明模拟器能够处理大量的 NEON 指令。

**总结第二部分的功能：**

这部分代码定义了 ARM64 模拟器的核心执行逻辑、寄存器访问机制（包括通用寄存器、向量寄存器和系统寄存器）、丰富的调试功能（断点、单步执行、寄存器和内存查看）、对 ARMv8.3 指针认证的支持，以及大量的用于模拟各种 ARM64 指令的辅助函数，特别是针对 NEON (SIMD) 指令的模拟。

**关于 `.tq` 后缀和 JavaScript 的关系：**

根据描述，如果 `simulator-arm64.h` 以 `.tq` 结尾，那它就是一个 V8 Torque 源代码。 Torque 是一种 V8 用于生成高效 TurboFan 代码的领域特定语言。 由于当前提供的文件名是 `.h`，这是一个 C++ 头文件，所以它不是 Torque 代码。

然而，即使是 C++ 模拟器，它的功能也与 JavaScript 的执行息息相关。 V8 使用这个模拟器来：

* **在没有硬件支持的平台上运行 JavaScript 代码。** 例如，在开发和测试阶段，或者在一些没有 ARM64 硬件的 CI 环境中。
* **进行代码调试和分析。** 模拟器可以提供比实际硬件更细粒度的控制和信息。

**JavaScript 示例 (与寄存器和内存操作相关)：**

尽管这个头文件是 C++ 代码，但其模拟的功能最终会影响 JavaScript 的执行。 例如，当 JavaScript 代码执行到需要进行算术运算或访问内存的时候，模拟器中的对应函数会被调用。

假设 JavaScript 代码中有以下操作：

```javascript
let a = 10;
let b = 20;
let sum = a + b;
console.log(sum);
```

当 V8 执行 `a + b` 时，在模拟器中，可能会涉及到以下操作（简化）：

1. **读取寄存器：** 模拟器会读取存储 `a` 和 `b` 值的虚拟寄存器（例如，通过 `wreg()` 或 `xreg()`）。
2. **执行加法：** 模拟器会调用一个类似 `AddSubHelper()` 的函数来模拟加法运算，并更新相应的标志位（例如，NZCV 寄存器）。
3. **写入寄存器：** 模拟器会将结果 `sum` 写入另一个虚拟寄存器（例如，通过 `set_wreg()` 或 `set_xreg()`）。
4. **内存访问 (console.log)：** 当执行 `console.log(sum)` 时，模拟器可能会模拟将 `sum` 的值写入到内存缓冲区，以便后续进行输出。这会涉及到 `MemoryWrite()` 或类似的函数。

**代码逻辑推理示例：**

假设有以下模拟器状态：

* `pc_` 指向地址 `0x1000`，该地址的指令是一个加法指令，将寄存器 `r0` 和 `r1` 的值相加，结果存入 `r2`。
* `registers_[0]` (对应 `r0`) 的值为 `5`。
* `registers_[1]` (对应 `r1`) 的值为 `10`。

当调用 `ExecuteInstruction()` 时：

1. `Decode(pc_)` 会解析 `0x1000` 地址的指令。
2. 模拟器会根据解码后的指令，调用相应的 `Visit` 函数来处理加法操作。
3. 在 `Visit` 函数中，会使用 `reg(0)` 和 `reg(1)` 读取 `r0` 和 `r1` 的值，得到 `5` 和 `10`。
4. 模拟器会执行加法 `5 + 10 = 15`。
5. 模拟器会使用 `set_reg(2, 15)` 将结果 `15` 写入 `registers_[2]` (对应 `r2`)。
6. `increment_pc()` 会将 `pc_` 的值更新为下一条指令的地址（例如 `0x1004`）。

**用户常见的编程错误示例：**

使用模拟器进行开发时，用户可能会遇到以下编程错误，这些错误会被模拟器捕捉到：

1. **访问未映射的内存：** 如果 JavaScript 代码尝试访问超出其分配内存范围的地址，模拟器的 `CheckMemoryAccess()` 或 `ProbeMemory()` 可能会检测到并报告错误。例如，访问一个未定义的数组索引。

   ```javascript
   let arr = [1, 2, 3];
   console.log(arr[5]); // 越界访问
   ```

2. **执行非法指令：** 如果生成的机器码包含模拟器不支持或非法的指令，解码过程可能会失败，或者模拟器会抛出异常。这通常发生在编译器或代码生成器出现错误时。

3. **寄存器使用错误：**  在编写汇编级别的代码（如果允许）或者理解编译器生成的代码时，可能会错误地假设寄存器的值或类型，导致模拟器执行出错。例如，将一个指针值误当成整数进行运算。

总而言之，这部分 `simulator-arm64.h` 代码是 V8 引擎在 ARM64 架构上模拟执行 JavaScript 代码的关键组成部分，它提供了指令级的模拟能力，并包含了丰富的调试和分析工具。

Prompt: 
```
这是目录为v8/src/execution/arm64/simulator-arm64.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/execution/arm64/simulator-arm64.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
e if (pc_->IsBti()) {
        CheckBTypeForBti();
      } else if (!pc_->IsException()) {
        FATAL("Executing non-BTI instruction with wrong BType.");
      }
    }
  }

  void ExecuteInstruction() {
    DCHECK(IsAligned(reinterpret_cast<uintptr_t>(pc_), kInstrSize));
    CheckBType();
    ResetBType();
    CheckBreakNext();
    Decode(pc_);
    increment_pc();
    LogAllWrittenRegisters();
    CheckBreakpoints();
  }

// Declare all Visitor functions.
#define DECLARE(A) void Visit##A(Instruction* instr);
  VISITOR_LIST(DECLARE)
#undef DECLARE
  void VisitNEON3SameFP(NEON3SameOp op, VectorFormat vf, SimVRegister& rd,
                        SimVRegister& rn, SimVRegister& rm);

  bool IsZeroRegister(unsigned code, Reg31Mode r31mode) const {
    return ((code == 31) && (r31mode == Reg31IsZeroRegister));
  }

  // Register accessors.
  // Return 'size' bits of the value of an integer register, as the specified
  // type. The value is zero-extended to fill the result.
  //
  template <typename T>
  T reg(unsigned code, Reg31Mode r31mode = Reg31IsZeroRegister) const {
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
    if (IsZeroRegister(code, r31mode)) {
      return 0;
    }
    return registers_[code].Get<T>();
  }

  // Common specialized accessors for the reg() template.
  int32_t wreg(unsigned code, Reg31Mode r31mode = Reg31IsZeroRegister) const {
    return reg<int32_t>(code, r31mode);
  }

  int64_t xreg(unsigned code, Reg31Mode r31mode = Reg31IsZeroRegister) const {
    return reg<int64_t>(code, r31mode);
  }

  enum RegLogMode { LogRegWrites, NoRegLog };

  // Write 'value' into an integer register. The value is zero-extended. This
  // behaviour matches AArch64 register writes.
  template <typename T>
  void set_reg(unsigned code, T value,
               Reg31Mode r31mode = Reg31IsZeroRegister) {
    set_reg_no_log(code, value, r31mode);
    LogRegister(code, r31mode);
  }

  // Common specialized accessors for the set_reg() template.
  void set_wreg(unsigned code, int32_t value,
                Reg31Mode r31mode = Reg31IsZeroRegister) {
    set_reg(code, value, r31mode);
  }

  void set_xreg(unsigned code, int64_t value,
                Reg31Mode r31mode = Reg31IsZeroRegister) {
    set_reg(code, value, r31mode);
  }

  // As above, but don't automatically log the register update.
  template <typename T>
  void set_reg_no_log(unsigned code, T value,
                      Reg31Mode r31mode = Reg31IsZeroRegister) {
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfRegisters));
    if (!IsZeroRegister(code, r31mode)) {
      registers_[code].Set(value);
    }
  }

  void set_wreg_no_log(unsigned code, int32_t value,
                       Reg31Mode r31mode = Reg31IsZeroRegister) {
    set_reg_no_log(code, value, r31mode);
  }

  void set_xreg_no_log(unsigned code, int64_t value,
                       Reg31Mode r31mode = Reg31IsZeroRegister) {
    set_reg_no_log(code, value, r31mode);
  }

  // Commonly-used special cases.
  template <typename T>
  void set_lr(T value) {
    DCHECK_EQ(sizeof(T), static_cast<unsigned>(kSystemPointerSize));
    set_reg(kLinkRegCode, value);
  }

  template <typename T>
  void set_sp(T value) {
    DCHECK_EQ(sizeof(T), static_cast<unsigned>(kSystemPointerSize));
    set_reg(31, value, Reg31IsStackPointer);
  }

  // Vector register accessors.
  // These are equivalent to the integer register accessors, but for vector
  // registers.

  // A structure for representing a 128-bit Q register.
  struct qreg_t {
    uint8_t val[kQRegSize];
  };

  // Basic accessor: read the register as the specified type.
  template <typename T>
  T vreg(unsigned code) const {
    static_assert((sizeof(T) == kBRegSize) || (sizeof(T) == kHRegSize) ||
                      (sizeof(T) == kSRegSize) || (sizeof(T) == kDRegSize) ||
                      (sizeof(T) == kQRegSize),
                  "Template type must match size of register.");
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));

    return vregisters_[code].Get<T>();
  }

  inline SimVRegister& vreg(unsigned code) { return vregisters_[code]; }

  int64_t sp() { return xreg(31, Reg31IsStackPointer); }
  int64_t fp() { return xreg(kFramePointerRegCode, Reg31IsStackPointer); }
  Instruction* lr() { return reg<Instruction*>(kLinkRegCode); }

  Address get_sp() const { return reg<Address>(31, Reg31IsStackPointer); }

  // Common specialized accessors for the vreg() template.
  uint8_t breg(unsigned code) const { return vreg<uint8_t>(code); }

  float hreg(unsigned code) const { return vreg<uint16_t>(code); }

  float sreg(unsigned code) const { return vreg<float>(code); }

  uint32_t sreg_bits(unsigned code) const { return vreg<uint32_t>(code); }

  double dreg(unsigned code) const { return vreg<double>(code); }

  uint64_t dreg_bits(unsigned code) const { return vreg<uint64_t>(code); }

  qreg_t qreg(unsigned code) const { return vreg<qreg_t>(code); }

  // As above, with parameterized size and return type. The value is
  // either zero-extended or truncated to fit, as required.
  template <typename T>
  T vreg(unsigned size, unsigned code) const {
    uint64_t raw = 0;
    T result;

    switch (size) {
      case kSRegSize:
        raw = vreg<uint32_t>(code);
        break;
      case kDRegSize:
        raw = vreg<uint64_t>(code);
        break;
      default:
        UNREACHABLE();
    }

    static_assert(sizeof(result) <= sizeof(raw),
                  "Template type must be <= 64 bits.");
    // Copy the result and truncate to fit. This assumes a little-endian host.
    memcpy(&result, &raw, sizeof(result));
    return result;
  }

  // Write 'value' into a floating-point register. The value is zero-extended.
  // This behaviour matches AArch64 register writes.
  template <typename T>
  void set_vreg(unsigned code, T value, RegLogMode log_mode = LogRegWrites) {
    static_assert(
        (sizeof(value) == kBRegSize) || (sizeof(value) == kHRegSize) ||
            (sizeof(value) == kSRegSize) || (sizeof(value) == kDRegSize) ||
            (sizeof(value) == kQRegSize),
        "Template type must match size of register.");
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
    vregisters_[code].Set(value);

    if (log_mode == LogRegWrites) {
      LogVRegister(code, GetPrintRegisterFormat(value));
    }
  }

  // Common specialized accessors for the set_vreg() template.
  void set_breg(unsigned code, int8_t value,
                RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  void set_hreg(unsigned code, int16_t value,
                RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  void set_sreg(unsigned code, float value,
                RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  void set_sreg_bits(unsigned code, uint32_t value,
                     RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  void set_dreg(unsigned code, double value,
                RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  void set_dreg_bits(unsigned code, uint64_t value,
                     RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  void set_qreg(unsigned code, qreg_t value,
                RegLogMode log_mode = LogRegWrites) {
    set_vreg(code, value, log_mode);
  }

  // As above, but don't automatically log the register update.
  template <typename T>
  void set_vreg_no_log(unsigned code, T value) {
    static_assert((sizeof(value) == kBRegSize) ||
                  (sizeof(value) == kHRegSize) ||
                  (sizeof(value) == kSRegSize) ||
                  (sizeof(value) == kDRegSize) || (sizeof(value) == kQRegSize));
    DCHECK_LT(code, static_cast<unsigned>(kNumberOfVRegisters));
    vregisters_[code].Set(value);
  }

  void set_breg_no_log(unsigned code, uint8_t value) {
    set_vreg_no_log(code, value);
  }

  void set_hreg_no_log(unsigned code, uint16_t value) {
    set_vreg_no_log(code, value);
  }

  void set_sreg_no_log(unsigned code, float value) {
    set_vreg_no_log(code, value);
  }

  void set_dreg_no_log(unsigned code, double value) {
    set_vreg_no_log(code, value);
  }

  void set_qreg_no_log(unsigned code, qreg_t value) {
    set_vreg_no_log(code, value);
  }

  SimSystemRegister& nzcv() { return nzcv_; }
  SimSystemRegister& fpcr() { return fpcr_; }
  FPRounding RMode() { return static_cast<FPRounding>(fpcr_.RMode()); }
  bool DN() { return fpcr_.DN() != 0; }

  // Debug helpers

  // Simulator breakpoints.
  struct Breakpoint {
    Instruction* location;
    bool enabled;
  };
  std::vector<Breakpoint> breakpoints_;
  void SetBreakpoint(Instruction* breakpoint);
  void ListBreakpoints();
  void CheckBreakpoints();

  // Helpers for the 'next' command.
  // When this is set, the Simulator will insert a breakpoint after the next BL
  // instruction it meets.
  bool break_on_next_;
  // Check if the Simulator should insert a break after the current instruction
  // for the 'next' command.
  void CheckBreakNext();

  // Disassemble instruction at the given address.
  void PrintInstructionsAt(Instruction* pc, uint64_t count);

  // Print all registers of the specified types.
  void PrintRegisters();
  void PrintVRegisters();
  void PrintSystemRegisters();

  // As above, but only print the registers that have been updated.
  void PrintWrittenRegisters();
  void PrintWrittenVRegisters();

  // As above, but respect LOG_REG and LOG_VREG.
  void LogWrittenRegisters() {
    if (log_parameters() & LOG_REGS) PrintWrittenRegisters();
  }
  void LogWrittenVRegisters() {
    if (log_parameters() & LOG_VREGS) PrintWrittenVRegisters();
  }
  void LogAllWrittenRegisters() {
    LogWrittenRegisters();
    LogWrittenVRegisters();
  }

  // Specify relevant register formats for Print(V)Register and related helpers.
  enum PrintRegisterFormat {
    // The lane size.
    kPrintRegLaneSizeB = 0 << 0,
    kPrintRegLaneSizeH = 1 << 0,
    kPrintRegLaneSizeS = 2 << 0,
    kPrintRegLaneSizeW = kPrintRegLaneSizeS,
    kPrintRegLaneSizeD = 3 << 0,
    kPrintRegLaneSizeX = kPrintRegLaneSizeD,
    kPrintRegLaneSizeQ = 4 << 0,

    kPrintRegLaneSizeOffset = 0,
    kPrintRegLaneSizeMask = 7 << 0,

    // The lane count.
    kPrintRegAsScalar = 0,
    kPrintRegAsDVector = 1 << 3,
    kPrintRegAsQVector = 2 << 3,

    kPrintRegAsVectorMask = 3 << 3,

    // Indicate floating-point format lanes. (This flag is only supported for S-
    // and D-sized lanes.)
    kPrintRegAsFP = 1 << 5,

    // Supported combinations.

    kPrintXReg = kPrintRegLaneSizeX | kPrintRegAsScalar,
    kPrintWReg = kPrintRegLaneSizeW | kPrintRegAsScalar,
    kPrintSReg = kPrintRegLaneSizeS | kPrintRegAsScalar | kPrintRegAsFP,
    kPrintDReg = kPrintRegLaneSizeD | kPrintRegAsScalar | kPrintRegAsFP,

    kPrintReg1B = kPrintRegLaneSizeB | kPrintRegAsScalar,
    kPrintReg8B = kPrintRegLaneSizeB | kPrintRegAsDVector,
    kPrintReg16B = kPrintRegLaneSizeB | kPrintRegAsQVector,
    kPrintReg1H = kPrintRegLaneSizeH | kPrintRegAsScalar,
    kPrintReg4H = kPrintRegLaneSizeH | kPrintRegAsDVector,
    kPrintReg8H = kPrintRegLaneSizeH | kPrintRegAsQVector,
    kPrintReg1S = kPrintRegLaneSizeS | kPrintRegAsScalar,
    kPrintReg2S = kPrintRegLaneSizeS | kPrintRegAsDVector,
    kPrintReg4S = kPrintRegLaneSizeS | kPrintRegAsQVector,
    kPrintReg1SFP = kPrintRegLaneSizeS | kPrintRegAsScalar | kPrintRegAsFP,
    kPrintReg2SFP = kPrintRegLaneSizeS | kPrintRegAsDVector | kPrintRegAsFP,
    kPrintReg4SFP = kPrintRegLaneSizeS | kPrintRegAsQVector | kPrintRegAsFP,
    kPrintReg1D = kPrintRegLaneSizeD | kPrintRegAsScalar,
    kPrintReg2D = kPrintRegLaneSizeD | kPrintRegAsQVector,
    kPrintReg1DFP = kPrintRegLaneSizeD | kPrintRegAsScalar | kPrintRegAsFP,
    kPrintReg2DFP = kPrintRegLaneSizeD | kPrintRegAsQVector | kPrintRegAsFP,
    kPrintReg1Q = kPrintRegLaneSizeQ | kPrintRegAsScalar
  };

  unsigned GetPrintRegLaneSizeInBytesLog2(PrintRegisterFormat format) {
    return (format & kPrintRegLaneSizeMask) >> kPrintRegLaneSizeOffset;
  }

  unsigned GetPrintRegLaneSizeInBytes(PrintRegisterFormat format) {
    return 1 << GetPrintRegLaneSizeInBytesLog2(format);
  }

  unsigned GetPrintRegSizeInBytesLog2(PrintRegisterFormat format) {
    if (format & kPrintRegAsDVector) return kDRegSizeLog2;
    if (format & kPrintRegAsQVector) return kQRegSizeLog2;

    // Scalar types.
    return GetPrintRegLaneSizeInBytesLog2(format);
  }

  unsigned GetPrintRegSizeInBytes(PrintRegisterFormat format) {
    return 1 << GetPrintRegSizeInBytesLog2(format);
  }

  unsigned GetPrintRegLaneCount(PrintRegisterFormat format) {
    unsigned reg_size_log2 = GetPrintRegSizeInBytesLog2(format);
    unsigned lane_size_log2 = GetPrintRegLaneSizeInBytesLog2(format);
    DCHECK_GE(reg_size_log2, lane_size_log2);
    return 1 << (reg_size_log2 - lane_size_log2);
  }

  template <typename T>
  PrintRegisterFormat GetPrintRegisterFormat(T value) {
    return GetPrintRegisterFormatForSize(sizeof(value));
  }

  PrintRegisterFormat GetPrintRegisterFormat(double value) {
    static_assert(sizeof(value) == kDRegSize,
                  "D register must be size of double.");
    return GetPrintRegisterFormatForSizeFP(sizeof(value));
  }

  PrintRegisterFormat GetPrintRegisterFormat(float value) {
    static_assert(sizeof(value) == kSRegSize,
                  "S register must be size of float.");
    return GetPrintRegisterFormatForSizeFP(sizeof(value));
  }

  PrintRegisterFormat GetPrintRegisterFormat(VectorFormat vform);
  PrintRegisterFormat GetPrintRegisterFormatFP(VectorFormat vform);

  PrintRegisterFormat GetPrintRegisterFormatForSize(size_t reg_size,
                                                    size_t lane_size);

  PrintRegisterFormat GetPrintRegisterFormatForSize(size_t size) {
    return GetPrintRegisterFormatForSize(size, size);
  }

  PrintRegisterFormat GetPrintRegisterFormatForSizeFP(size_t size) {
    switch (size) {
      default:
        UNREACHABLE();
      case kDRegSize:
        return kPrintDReg;
      case kSRegSize:
        return kPrintSReg;
    }
  }

  PrintRegisterFormat GetPrintRegisterFormatTryFP(PrintRegisterFormat format) {
    if ((GetPrintRegLaneSizeInBytes(format) == kSRegSize) ||
        (GetPrintRegLaneSizeInBytes(format) == kDRegSize)) {
      return static_cast<PrintRegisterFormat>(format | kPrintRegAsFP);
    }
    return format;
  }

  // Print individual register values (after update).
  void PrintRegister(unsigned code, Reg31Mode r31mode = Reg31IsStackPointer);
  void PrintVRegister(unsigned code, PrintRegisterFormat sizes);
  void PrintSystemRegister(SystemRegister id);

  // Like Print* (above), but respect log_parameters().
  void LogRegister(unsigned code, Reg31Mode r31mode = Reg31IsStackPointer) {
    if (log_parameters() & LOG_REGS) PrintRegister(code, r31mode);
  }
  void LogVRegister(unsigned code, PrintRegisterFormat format) {
    if (log_parameters() & LOG_VREGS) PrintVRegister(code, format);
  }
  void LogSystemRegister(SystemRegister id) {
    if (log_parameters() & LOG_SYS_REGS) PrintSystemRegister(id);
  }

  // Print memory accesses.
  void PrintRead(uintptr_t address, unsigned reg_code,
                 PrintRegisterFormat format);
  void PrintWrite(uintptr_t address, unsigned reg_code,
                  PrintRegisterFormat format);
  void PrintVRead(uintptr_t address, unsigned reg_code,
                  PrintRegisterFormat format, unsigned lane);
  void PrintVWrite(uintptr_t address, unsigned reg_code,
                   PrintRegisterFormat format, unsigned lane);

  // Like Print* (above), but respect log_parameters().
  void LogRead(uintptr_t address, unsigned reg_code,
               PrintRegisterFormat format) {
    if (log_parameters() & LOG_REGS) PrintRead(address, reg_code, format);
  }
  void LogWrite(uintptr_t address, unsigned reg_code,
                PrintRegisterFormat format) {
    if (log_parameters() & LOG_WRITE) PrintWrite(address, reg_code, format);
  }
  void LogVRead(uintptr_t address, unsigned reg_code,
                PrintRegisterFormat format, unsigned lane = 0) {
    if (log_parameters() & LOG_VREGS) {
      PrintVRead(address, reg_code, format, lane);
    }
  }
  void LogVWrite(uintptr_t address, unsigned reg_code,
                 PrintRegisterFormat format, unsigned lane = 0) {
    if (log_parameters() & LOG_WRITE) {
      PrintVWrite(address, reg_code, format, lane);
    }
  }

  int log_parameters() { return log_parameters_; }
  void set_log_parameters(int new_parameters) {
    log_parameters_ = new_parameters;
    if (!decoder_) {
      if (new_parameters & LOG_DISASM) {
        PrintF("Run --debug-sim to dynamically turn on disassembler\n");
      }
      return;
    }
    if (new_parameters & LOG_DISASM) {
      decoder_->InsertVisitorBefore(print_disasm_, this);
    } else {
      decoder_->RemoveVisitor(print_disasm_);
    }
  }

  // Helper functions for register tracing.
  void PrintRegisterRawHelper(unsigned code, Reg31Mode r31mode,
                              int size_in_bytes = kXRegSize);
  void PrintVRegisterRawHelper(unsigned code, int bytes = kQRegSize,
                               int lsb = 0);
  void PrintVRegisterFPHelper(unsigned code, unsigned lane_size_in_bytes,
                              int lane_count = 1, int rightmost_lane = 0);

  static inline const char* WRegNameForCode(
      unsigned code, Reg31Mode mode = Reg31IsZeroRegister);
  static inline const char* XRegNameForCode(
      unsigned code, Reg31Mode mode = Reg31IsZeroRegister);
  static inline const char* SRegNameForCode(unsigned code);
  static inline const char* DRegNameForCode(unsigned code);
  static inline const char* VRegNameForCode(unsigned code);
  static inline int CodeFromName(const char* name);

  enum PointerType { kDataPointer, kInstructionPointer };

  struct PACKey {
    uint64_t high;
    uint64_t low;
    int number;
  };

  static V8_EXPORT_PRIVATE const PACKey kPACKeyIB;

  // Current implementation is that all pointers are tagged.
  static bool HasTBI(uint64_t ptr, PointerType type) {
    USE(ptr, type);
    return true;
  }

  // Current implementation uses 48-bit virtual addresses.
  static int GetBottomPACBit(uint64_t ptr, int ttbr) {
    USE(ptr, ttbr);
    DCHECK((ttbr == 0) || (ttbr == 1));
    return 48;
  }

  // The top PAC bit is 55 for the purposes of relative bit fields with TBI,
  // however bit 55 is the TTBR bit regardless of TBI so isn't part of the PAC
  // codes in pointers.
  static int GetTopPACBit(uint64_t ptr, PointerType type) {
    return HasTBI(ptr, type) ? 55 : 63;
  }

  // Armv8.3 Pointer authentication helpers.
  V8_EXPORT_PRIVATE static uint64_t CalculatePACMask(uint64_t ptr,
                                                     PointerType type,
                                                     int ext_bit);
  V8_EXPORT_PRIVATE static uint64_t ComputePAC(uint64_t data, uint64_t context,
                                               PACKey key);
  V8_EXPORT_PRIVATE static uint64_t AuthPAC(uint64_t ptr, uint64_t context,
                                            PACKey key, PointerType type);
  V8_EXPORT_PRIVATE static uint64_t AddPAC(uint64_t ptr, uint64_t context,
                                           PACKey key, PointerType type);
  V8_EXPORT_PRIVATE static uint64_t StripPAC(uint64_t ptr, PointerType type);

 protected:
  // Simulation helpers ------------------------------------
  bool ConditionPassed(Condition cond) {
    SimSystemRegister& flags = nzcv();
    switch (cond) {
      case eq:
        return flags.Z();
      case ne:
        return !flags.Z();
      case hs:
        return flags.C();
      case lo:
        return !flags.C();
      case mi:
        return flags.N();
      case pl:
        return !flags.N();
      case vs:
        return flags.V();
      case vc:
        return !flags.V();
      case hi:
        return flags.C() && !flags.Z();
      case ls:
        return !(flags.C() && !flags.Z());
      case ge:
        return flags.N() == flags.V();
      case lt:
        return flags.N() != flags.V();
      case gt:
        return !flags.Z() && (flags.N() == flags.V());
      case le:
        return !(!flags.Z() && (flags.N() == flags.V()));
      case nv:  // Fall through.
      case al:
        return true;
      default:
        UNREACHABLE();
    }
  }

  bool ConditionFailed(Condition cond) { return !ConditionPassed(cond); }

  template <typename T>
  void AddSubHelper(Instruction* instr, T op2);
  template <typename T>
  T AddWithCarry(bool set_flags, T left, T right, int carry_in = 0);
  template <typename T>
  void AddSubWithCarry(Instruction* instr);
  template <typename T>
  void LogicalHelper(Instruction* instr, T op2);
  template <typename T>
  void ConditionalCompareHelper(Instruction* instr, T op2);
  void LoadStoreHelper(Instruction* instr, int64_t offset, AddrMode addrmode);
  void LoadStorePairHelper(Instruction* instr, AddrMode addrmode);
  template <typename T>
  void CompareAndSwapHelper(const Instruction* instr);
  template <typename T>
  void CompareAndSwapPairHelper(const Instruction* instr);
  template <typename T>
  void AtomicMemorySimpleHelper(const Instruction* instr);
  template <typename T>
  void AtomicMemorySwapHelper(const Instruction* instr);
  uintptr_t LoadStoreAddress(unsigned addr_reg, int64_t offset,
                             AddrMode addrmode);
  void LoadStoreWriteBack(unsigned addr_reg, int64_t offset, AddrMode addrmode);
  void NEONLoadStoreMultiStructHelper(const Instruction* instr,
                                      AddrMode addr_mode);
  void NEONLoadStoreSingleStructHelper(const Instruction* instr,
                                       AddrMode addr_mode);
  void CheckMemoryAccess(uintptr_t address, uintptr_t stack);

  // "Probe" if an address range can be read. This is currently implemented
  // by doing a 1-byte read of the last accessed byte, since the assumption is
  // that if the last byte is accessible, also all lower bytes are accessible
  // (which holds true for Wasm).
  // Returns true if the access was successful, false if the access raised a
  // signal which was then handled by the trap handler (also see
  // {trap_handler::ProbeMemory}). If the access raises a signal which is not
  // handled by the trap handler (e.g. because the current PC is not registered
  // as a protected instruction), the signal will propagate and make the process
  // crash. If no trap handler is available, this always returns true.
  bool ProbeMemory(uintptr_t address, uintptr_t access_size);

  // Memory read helpers.
  template <typename T, typename A>
  T MemoryRead(A address) {
    T value;
    static_assert((sizeof(value) == 1) || (sizeof(value) == 2) ||
                  (sizeof(value) == 4) || (sizeof(value) == 8) ||
                  (sizeof(value) == 16));
    memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return value;
  }

  // Memory write helpers.
  template <typename T, typename A>
  void MemoryWrite(A address, T value) {
    static_assert((sizeof(value) == 1) || (sizeof(value) == 2) ||
                  (sizeof(value) == 4) || (sizeof(value) == 8) ||
                  (sizeof(value) == 16));
    memcpy(reinterpret_cast<void*>(address), &value, sizeof(value));
  }

  template <typename T>
  T ShiftOperand(T value, Shift shift_type, unsigned amount);
  template <typename T>
  T ExtendValue(T value, Extend extend_type, unsigned left_shift = 0);
  template <typename T>
  void Extract(Instruction* instr);
  template <typename T>
  void DataProcessing2Source(Instruction* instr);
  template <typename T>
  void BitfieldHelper(Instruction* instr);
  uint16_t PolynomialMult(uint8_t op1, uint8_t op2);
  sim_uint128_t PolynomialMult128(uint64_t op1, uint64_t op2,
                                  int lane_size_in_bits) const;
  sim_uint128_t Lsl128(sim_uint128_t x, unsigned shift) const;
  sim_uint128_t Eor128(sim_uint128_t x, sim_uint128_t y) const;

  void ld1(VectorFormat vform, LogicVRegister dst, uint64_t addr);
  void ld1(VectorFormat vform, LogicVRegister dst, int index, uint64_t addr);
  void ld1r(VectorFormat vform, LogicVRegister dst, uint64_t addr);
  void ld2(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
           uint64_t addr);
  void ld2(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
           int index, uint64_t addr);
  void ld2r(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
            uint64_t addr);
  void ld3(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
           LogicVRegister dst3, uint64_t addr);
  void ld3(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
           LogicVRegister dst3, int index, uint64_t addr);
  void ld3r(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
            LogicVRegister dst3, uint64_t addr);
  void ld4(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
           LogicVRegister dst3, LogicVRegister dst4, uint64_t addr);
  void ld4(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
           LogicVRegister dst3, LogicVRegister dst4, int index, uint64_t addr);
  void ld4r(VectorFormat vform, LogicVRegister dst1, LogicVRegister dst2,
            LogicVRegister dst3, LogicVRegister dst4, uint64_t addr);
  void st1(VectorFormat vform, LogicVRegister src, uint64_t addr);
  void st1(VectorFormat vform, LogicVRegister src, int index, uint64_t addr);
  void st2(VectorFormat vform, LogicVRegister src, LogicVRegister src2,
           uint64_t addr);
  void st2(VectorFormat vform, LogicVRegister src, LogicVRegister src2,
           int index, uint64_t addr);
  void st3(VectorFormat vform, LogicVRegister src, LogicVRegister src2,
           LogicVRegister src3, uint64_t addr);
  void st3(VectorFormat vform, LogicVRegister src, LogicVRegister src2,
           LogicVRegister src3, int index, uint64_t addr);
  void st4(VectorFormat vform, LogicVRegister src, LogicVRegister src2,
           LogicVRegister src3, LogicVRegister src4, uint64_t addr);
  void st4(VectorFormat vform, LogicVRegister src, LogicVRegister src2,
           LogicVRegister src3, LogicVRegister src4, int index, uint64_t addr);
  LogicVRegister cmp(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     Condition cond);
  LogicVRegister cmp(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, int imm, Condition cond);
  LogicVRegister cmptst(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister add(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister addp(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister mla(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister mls(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister mul(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2);
  LogicVRegister mul(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     int index);
  LogicVRegister mla(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     int index);
  LogicVRegister mls(VectorFormat vform, LogicVRegister dst,
                     const LogicVRegister& src1, const LogicVRegister& src2,
                     int index);
  LogicVRegister pmul(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2);

  using ByElementOp = LogicVRegister (Simulator::*)(VectorFormat vform,
                                                    LogicVRegister dst,
                                                    const LogicVRegister& src1,
                                                    const LogicVRegister& src2,
                                                    int index);
  LogicVRegister fmul(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      int index);
  LogicVRegister fmla(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      int index);
  LogicVRegister fmls(VectorFormat vform, LogicVRegister dst,
                      const LogicVRegister& src1, const LogicVRegister& src2,
                      int index);
  LogicVRegister fmulx(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister smull(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister smull2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2,
                        int index);
  LogicVRegister umull(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister umull2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2,
                        int index);
  LogicVRegister smlal(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister smlal2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2,
                        int index);
  LogicVRegister umlal(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister umlal2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2,
                        int index);
  LogicVRegister smlsl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister smlsl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2,
                        int index);
  LogicVRegister umlsl(VectorFormat vform, LogicVRegister dst,
                       const LogicVRegister& src1, const LogicVRegister& src2,
                       int index);
  LogicVRegister umlsl2(VectorFormat vform, LogicVRegister dst,
                        const LogicVRegister& src1, const LogicVRegister& src2,
                        int index);
  LogicVRegister sqdmull(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         int index);
  LogicVRegister sqdmull2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, int index);
  LogicVRegister sqdmlal(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         int index);
  LogicVRegister sqdmlal2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, int index);
  LogicVRegister sqdmlsl(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         int index);
  LogicVRegister sqdmlsl2(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                          const LogicVRegister& src2, int index);
  LogicVRegister sqdmulh(VectorFormat vform, LogicVRegister dst,
                         const LogicVRegister& src1, const LogicVRegister& src2,
                         int index);
  LogicVRegister sqrdmulh(VectorFormat vform, LogicVRegister dst,
                          const LogicVRegister& src1,
                      
"""


```