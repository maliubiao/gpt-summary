Response:
My thinking process to analyze the provided C++ header file involved these steps:

1. **Initial Skim and Keyword Recognition:** I first quickly scanned the code, looking for familiar C++ keywords and patterns. I noticed: `#ifndef`, `#define`, `#include`, `namespace`, `class`, `inline`, `constexpr`, `switch`, `case`, `return`, `struct`, `template`, `using`, `explicit`, `Register`, `DoubleRegister`, `Label`, `Condition`, `MemOperand`, `Operand`, `Handle`, `AbortReason`, and function names like `Load`, `Store`, `Compare`, `Add`, `Sub`, `Push`, `Move`, `Call`, etc. This gave me a general sense that this is low-level code dealing with memory, registers, and conditional execution, likely related to code generation.

2. **Identifying Core Functionality Areas:** Based on the keywords and function names, I started to group related functionalities. I saw code dealing with:
    * **Conditions and Comparisons:**  `ConditionForFloat64`, `ConditionToConditionCmpFPU`, `MapCompare`, `CompareRoot`, `CmpTagged`, `IsRootConstant`.
    * **Registers and Memory Access:**  `TemporaryRegisterScope`, `AcquireScratch`, `AcquireScratchDouble`, `MemOperand`, `StackSlotOperand`, `GetStackSlot`, `ToMemOperand`, `Load...`, `Store...`, `BuildTypedArrayDataPointer`, `TypedArrayElementOperand`, `DataViewElementOperand`, `LoadTaggedFieldByIndex`, `LoadFixedArrayElement`, `StoreFixedArrayElement`.
    * **Arithmetic and Logical Operations:** `ShiftFromScale`, `SmiTagInt32AndSetFlags`, `CheckInt32IsSmi`, `SmiAddConstant`, `SmiSubConstant`, `Add32`, `Sub32`, `And`, `Or`, `ShiftLeft`, `NegateInt32`.
    * **Control Flow:** `BindJumpTarget`, `BindBlock`, `Call`, `Assert`.
    * **Data Handling and Conversion:** `MoveHeapNumber`, `Move`, `LoadFloat...`, `StoreFloat...`, `SignExtend32To64Bits`, `ToUint8Clamped`.
    * **Stack Management:** `Push`, `PushReverse`, `EmitEnterExitFrame`.

3. **Analyzing Specific Code Blocks:** I then started to look closer at specific blocks of code to understand their purpose:
    * **`ConditionForFloat64` and `ConditionToConditionCmpFPU`:** These functions clearly map higher-level `Operation` and `Condition` enums to lower-level FPU condition codes, suggesting an interface with floating-point hardware.
    * **`ShiftFromScale`:**  This looks like a helper function to calculate bit shifts based on scaling factors, common in memory addressing.
    * **`TemporaryRegisterScope`:** This is a crucial pattern for managing register allocation within a specific code region, preventing register conflicts. The `AcquireScratch` and `IncludeScratch` methods are key to this.
    * **`MapCompare`:** This class is designed for efficiently checking the map (type information) of an object, a fundamental operation in dynamically typed languages.
    * **The `detail` namespace:** This often contains helper functions and templates used internally by the main class. The `ToRegister`, `PushAllHelper`, and `CountPushHelper` templates are good examples of generic programming techniques used for argument handling.
    * **Smi-related functions:**  The functions prefixed with "Smi" deal with Small Integers, a common optimization in V8. They handle tagging, untagging, and overflow checks.
    * **Load/Store functions:** The various `Load...` and `Store...` functions highlight the different data types and memory access patterns supported. The distinction between tagged and untagged, and the presence of "NoWriteBarrier" versions, are important for garbage collection.

4. **Considering the File Name and Context:** The file path `v8/src/maglev/riscv/maglev-assembler-riscv-inl.h` strongly suggests that this is part of the Maglev compiler (an intermediate tier in V8's compilation pipeline) and is specifically for the RISC-V architecture. The `.inl.h` suffix indicates an inline header file, meant to be included in other C++ files.

5. **Inferring High-Level Functionality:**  Combining the analysis of specific code blocks with the file name and context, I concluded that this header file defines the core building blocks for generating RISC-V machine code within the Maglev compiler. It provides an abstraction layer over the raw RISC-V instructions, making it easier to generate optimized code for JavaScript execution.

6. **Addressing Specific Questions (Torque, JavaScript, Logic, Errors):**
    * **Torque:** The `.h` extension confirms it's a C++ header, not a Torque file.
    * **JavaScript Relationship:**  The operations performed in this file (object property access, arithmetic, comparisons, function calls) are all fundamental to JavaScript execution. The code generated using these building blocks directly implements JavaScript semantics.
    * **Logic:**  I looked for functions with clear input/output relationships, like `ShiftFromScale` or the Smi manipulation functions.
    * **Errors:**  The `Assert...` functions and checks for Smi tagging indicate potential runtime errors that can occur if assumptions are violated.

7. **Synthesizing the Summary:** Finally, I combined all the gathered information into a concise summary, highlighting the key functionalities and the overall purpose of the header file. I focused on its role as a code generation tool for the Maglev compiler on the RISC-V architecture.
这是 V8 引擎中 Maglev 编译器的 RISC-V 架构特定汇编器头文件。它定义了用于生成 RISC-V 汇编指令的内联函数和辅助类。

根据您的描述，我们来分析一下它的功能：

**核心功能归纳：RISC-V 汇编代码生成构建块**

`v8/src/maglev/riscv/maglev-assembler-riscv-inl.h` 提供了在 V8 的 Maglev 编译器中，针对 RISC-V 架构生成机器码的底层工具。它类似于一个指令集的抽象层，让 Maglev 编译器可以用更高级的方式来构造 RISC-V 汇编代码，而无需直接操作原始的汇编指令字符串。

**具体功能分解：**

1. **条件码处理:**
   - `ConditionForFloat64(Operation operation)`:  可能将高级操作（`Operation`）转换为浮点数比较所需的 RISC-V 条件码。
   - `ConditionToConditionCmpFPU(Condition condition)`: 将通用的 `Condition` 枚举值映射到 RISC-V 浮点比较指令所需的条件码（例如 EQ, NE, LT, GE 等）。

2. **内存寻址辅助:**
   - `ShiftFromScale(int n)`:  根据比例因子（1, 2, 4, 8）计算出 RISC-V 移位操作所需的移位量。这常用于数组元素的寻址。

3. **临时寄存器管理:**
   - `MaglevAssembler::TemporaryRegisterScope`:  这是一个用于管理临时寄存器分配的类。它可以帮助在生成代码时安全地获取和释放寄存器，避免寄存器冲突。
     - `AcquireScratch()`:  获取一个通用目的的临时寄存器。
     - `AcquireScratchDouble()`: 获取一个浮点临时寄存器。
     - `IncludeScratch()`: 将指定的寄存器添加到可用的临时寄存器列表中。
     - `CopyForDefer()`: 用于延迟代码生成的上下文保存。

4. **Map 对象比较:**
   - `MapCompare`:  用于比较对象的 Map (类型信息)。这在动态类型语言中非常重要，用于判断对象的类型。
     - `Generate(Handle<Map> map, Condition cond, Label* if_true, Label::Distance distance)`:  生成比较 Map 的代码，如果条件满足则跳转到指定标签。
     - `GetMap()`:  获取 Map 对象的寄存器。

5. **参数处理和寄存器分配:**
   - `detail::AlreadyInARegister`:  检查一个参数是否已经存在于寄存器中，避免不必要的加载。
   - `detail::ToRegister`:  将不同类型的参数（立即数、内存位置等）加载到寄存器中。
   - `detail::PushAllHelper` 和 `detail::PushInput`:  辅助函数，用于将不同类型的参数压入栈中。

6. **栈操作:**
   - `Push(T... vals)`: 将一个或多个值压入栈。
   - `PushReverse(T... vals)`:  以相反的顺序将值压入栈。
   - `BindJumpTarget(Label* label)` 和 `BindBlock(BasicBlock* block)`: 用于绑定跳转目标和代码块。

7. **Smi (Small Integer) 处理:**
   - `CheckSmi(Register src)`:  检查一个寄存器中的值是否是 Smi。
   - `SmiTagInt32AndSetFlags(Register dst, Register src)`: 将 32 位整数转换为 Smi 并设置标志位（用于溢出检测）。
   - `CheckInt32IsSmi(Register maybeSmi, Label* fail, Register scratch)`: 检查一个值是否是 Smi 编码的 32 位整数。
   - `SmiAddConstant`, `SmiSubConstant`:  对 Smi 进行加减常数操作，并处理溢出。

8. **常量加载:**
   - `MoveHeapNumber(Register dst, double value)`: 将双精度浮点数加载到寄存器中。

9. **根对象比较:**
   - `CompareRoot(const Register& obj, RootIndex index, ComparisonMode mode)`: 将寄存器中的对象与根对象表中的特定项进行比较。
   - `CompareTaggedRoot(const Register& obj, RootIndex index)`: 比较寄存器中的标记对象与根对象。
   - `IsRootConstant(Input input, RootIndex root_index)`: 检查输入是否为特定的根常量。

10. **内存操作:**
    - `StackSlotOperand(StackSlot slot)`:  计算栈槽的内存操作数。
    - `GetStackSlot(const compiler::AllocatedOperand& operand)` 和 `ToMemOperand(...)`: 获取与操作数关联的内存操作数。
    - `BuildTypedArrayDataPointer(Register data_pointer, Register object)`: 计算 TypedArray 的数据指针。
    - `TypedArrayElementOperand`, `DataViewElementOperand`: 计算 TypedArray 和 DataView 元素的内存操作数。
    - `LoadTaggedFieldByIndex`, `LoadBoundedSizeFromObject`, `LoadExternalPointerField`: 加载对象的字段。
    - `LoadFixedArrayElement`, `LoadFixedDoubleArrayElement`: 加载 FixedArray 的元素。
    - `StoreFixedDoubleArrayElement`: 存储 FixedArray 的双精度浮点数元素。
    - `LoadSignedField`, `LoadUnsignedField`: 加载有符号和无符号字段。
    - `SetSlotAddressForTaggedField`, `SetSlotAddressForFixedArrayElement`: 计算字段或数组元素的地址。
    - `StoreTaggedFieldNoWriteBarrier`, `StoreFixedArrayElementNoWriteBarrier`, `StoreTaggedSignedField`, `StoreInt32Field`, `StoreField`: 存储值到对象的字段或数组元素中（部分操作没有写屏障）。

11. **原子操作和位操作:**
    - `ReverseByteOrder`: 反转字节序。
    - `IncrementInt32`, `DecrementInt32`, `AddInt32`, `AndInt32`, `OrInt32`, `ShiftLeft`:  基本的算术和位操作。

12. **控制流:**
    - `Call(Label* target)`:  调用指定标签的代码。
    - `EmitEnterExitFrame`:  生成进入和退出函数帧的代码。

13. **数据移动:**
    - `Move(...)`:  在寄存器、内存和常量之间移动数据。

14. **浮点数操作:**
    - `LoadFloat32`, `StoreFloat32`, `LoadFloat64`, `StoreFloat64`:  加载和存储单精度和双精度浮点数。
    - `LoadUnalignedFloat64`, `StoreUnalignedFloat64`, `ReverseByteOrderAndStoreUnalignedFloat64`: 处理未对齐的浮点数加载和存储，以及字节序转换。

15. **类型转换:**
    - `SignExtend32To64Bits`: 将 32 位有符号数扩展到 64 位。
    - `NegateInt32`:  取反 32 位整数。
    - `ToUint8Clamped`: 将浮点数转换为 0-255 范围内的无符号 8 位整数（带 clamp 操作）。

**关于 .tq 结尾：**

您是对的，如果文件名以 `.tq` 结尾，那通常表示这是一个 V8 Torque 源代码文件。但是，`v8/src/maglev/riscv/maglev-assembler-riscv-inl.h` 以 `.h` 结尾，明确表明这是一个 C++ 头文件。

**与 JavaScript 的关系：**

这个头文件中的功能是 Maglev 编译器将 JavaScript 代码转换为高效的 RISC-V 机器码的关键部分。JavaScript 的各种操作，例如属性访问、算术运算、类型检查、函数调用等，都需要通过底层的机器码来实现。`maglev-assembler-riscv-inl.h` 提供的工具就是用来生成这些机器码的。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = 10;
let sum = add(x, y);
```

当 Maglev 编译器编译上述 JavaScript 代码时，`maglev-assembler-riscv-inl.h` 中定义的函数会被用来生成相应的 RISC-V 汇编指令，例如：

- **加载变量 `x` 和 `y` 的值到寄存器：**  可能会使用 `MaglevAssembler::Move(Register dst, StackSlot src)` 或 `MaglevAssembler::LoadWord(Register dst, MemOperand src)`。
- **执行加法运算：** 可能会使用 `MaglevAssembler::AddInt32(Register reg, int amount)` 或更底层的 RISC-V 加法指令。
- **存储结果到变量 `sum`：** 可能会使用 `MaglevAssembler::Move(StackSlot dst, Register src)` 或 `MaglevAssembler::StoreWord(MemOperand dst, Register src)`。
- **函数调用 `add`：** 可能会使用 `MaglevAssembler::Call(Label* target)`，并涉及栈帧的设置和清理 (`MaglevAssembler::EmitEnterExitFrame`)。

**代码逻辑推理示例：**

**假设输入：**

- `n = 4` 作为 `ShiftFromScale` 函数的输入。

**输出：**

- `ShiftFromScale(4)` 将返回 `2`。

**推理：**

`ShiftFromScale` 函数内部的 `switch` 语句会匹配 `case 4:`，然后返回 `2`。这是因为比例因子 4 对应于将地址乘以 2 的 2 次方（左移 2 位）。

**用户常见的编程错误示例：**

如果开发者在 Maglev 编译器中手动管理寄存器而不使用 `TemporaryRegisterScope`，可能会导致 **寄存器冲突**。例如：

```c++
// 错误示例 (简化)
Register reg1 = masm->AcquireSomeRegister();
Register reg2 = masm->AcquireSomeRegister(); // 假设这里开发者错误地认为可以随意获取寄存器

masm->Add32(reg1, reg1, Operand(10));
masm->Add32(reg2, reg2, Operand(5));
// ... 某些操作可能会意外修改 reg1 的值 ...
masm->StoreWord(MemOperand(address), reg1); // 此时 reg1 的值可能不是预期的
```

在这个例子中，如果 `AcquireSomeRegister()` 只是简单地返回一个寄存器而不跟踪其使用情况，那么 `reg1` 和 `reg2` 可能指向同一个物理寄存器，导致数据被意外覆盖。 `TemporaryRegisterScope` 的作用就是避免这种错误，它会确保分配的临时寄存器不会与其他正在使用的寄存器冲突。

**总结：**

`v8/src/maglev/riscv/maglev-assembler-riscv-inl.h` 是一个关键的底层头文件，为 V8 引擎的 Maglev 编译器在 RISC-V 架构上生成高效机器码提供了基础的构建块。它抽象了 RISC-V 指令集的细节，并提供了用于寄存器管理、内存操作、条件判断、类型处理等方面的工具，使得编译器能够将 JavaScript 代码转换为可以在 RISC-V 处理器上执行的指令。

### 提示词
```
这是目录为v8/src/maglev/riscv/maglev-assembler-riscv-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/riscv/maglev-assembler-riscv-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_RISCV_MAGLEV_ASSEMBLER_RISCV_INL_H_
#define V8_MAGLEV_RISCV_MAGLEV_ASSEMBLER_RISCV_INL_H_

#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/maglev/maglev-assembler.h"
#include "src/maglev/maglev-basic-block.h"
#include "src/maglev/maglev-code-gen-state.h"
#include "src/maglev/maglev-ir.h"
#include "src/roots/static-roots.h"

namespace v8 {
namespace internal {
namespace maglev {

constexpr Condition ConditionForFloat64(Operation operation) {
  return ConditionFor(operation);
}

inline int ShiftFromScale(int n) {
  switch (n) {
    case 1:
      return 0;
    case 2:
      return 1;
    case 4:
      return 2;
    case 8:
      return 3;
    default:
      UNREACHABLE();
  }
}

inline FPUCondition ConditionToConditionCmpFPU(Condition condition) {
  switch (condition) {
    case kEqual:
      return EQ;
    case kNotEqual:
      return NE;
    case kUnsignedLessThan:
    case kLessThan:
      return LT;
    case kUnsignedGreaterThanEqual:
    case kGreaterThanEqual:
      return GE;
    case kUnsignedLessThanEqual:
    case kLessThanEqual:
      return LE;
    case kUnsignedGreaterThan:
    case kGreaterThan:
      return GT;
    default:
      break;
  }
  UNREACHABLE();
}

class MaglevAssembler::TemporaryRegisterScope
    : public TemporaryRegisterScopeBase<TemporaryRegisterScope> {
  using Base = TemporaryRegisterScopeBase<TemporaryRegisterScope>;

 public:
  struct SavedData : public Base::SavedData {
    RegList available_scratch_;
    DoubleRegList available_fp_scratch_;
  };

  explicit TemporaryRegisterScope(MaglevAssembler* masm)
      : Base(masm), scratch_scope_(masm) {
    if (prev_scope_ == nullptr) {
      // Add extra scratch register if no previous scope.
      scratch_scope_.Include(kMaglevExtraScratchRegister);
    }
  }
  explicit TemporaryRegisterScope(MaglevAssembler* masm,
                                  const SavedData& saved_data)
      : Base(masm, saved_data), scratch_scope_(masm) {
    scratch_scope_.SetAvailable(saved_data.available_scratch_);
    scratch_scope_.SetAvailableDouble(saved_data.available_fp_scratch_);
  }

  Register AcquireScratch() {
    Register reg = scratch_scope_.Acquire();
    CHECK(!available_.has(reg));
    return reg;
  }
  DoubleRegister AcquireScratchDouble() {
    DoubleRegister reg = scratch_scope_.AcquireDouble();
    CHECK(!available_double_.has(reg));
    return reg;
  }
  void IncludeScratch(Register reg) { scratch_scope_.Include(reg); }

  SavedData CopyForDefer() {
    return SavedData{
        CopyForDeferBase(),
        scratch_scope_.Available(),
        scratch_scope_.AvailableDouble(),
    };
  }

  void ResetToDefaultImpl() {
    scratch_scope_.SetAvailable(Assembler::DefaultTmpList() |
                                kMaglevExtraScratchRegister);
    scratch_scope_.SetAvailableDouble(Assembler::DefaultFPTmpList());
  }

 private:
  UseScratchRegisterScope scratch_scope_;
};

inline MapCompare::MapCompare(MaglevAssembler* masm, Register object,
                              size_t map_count)
    : masm_(masm), object_(object), map_count_(map_count) {
  map_ = masm_->scratch_register_scope()->AcquireScratch();
  if (PointerCompressionIsEnabled()) {
    masm_->LoadCompressedMap(map_, object_);
  } else {
    masm_->LoadMap(map_, object_);
  }
  USE(map_count_);
}

void MapCompare::Generate(Handle<Map> map, Condition cond, Label* if_true,
                          Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(masm_);
  Register temp = temps.AcquireScratch();
  masm_->Move(temp, map);
  // FIXME: reimplement with CmpTagged/JumpIf
  if (COMPRESS_POINTERS_BOOL) {
    masm_->Sub32(temp, map_, temp);
  } else {
    masm_->SubWord(temp, map_, temp);
  }
  masm_->MacroAssembler::Branch(if_true, cond, temp, Operand(zero_reg),
                                distance);
}

Register MapCompare::GetMap() {
  if (PointerCompressionIsEnabled()) {
    masm_->DecompressTagged(map_, map_);
  }
  return map_;
}

int MapCompare::TemporaryCount(size_t map_count) { return 1; }

namespace detail {

// Check if the argument is already in a register and doesn't need any
// scratches to reload. This should be in sync with `ToRegister` function below.
template <typename Arg>
inline bool AlreadyInARegister(Arg arg) {
  return false;
}

inline bool AlreadyInARegister(Register reg) { return true; }

inline bool AlreadyInARegister(const Input& input) {
  if (input.operand().IsConstant()) {
    return false;
  }
  const compiler::AllocatedOperand& operand =
      compiler::AllocatedOperand::cast(input.operand());
  if (operand.IsRegister()) {
    return true;
  }
  DCHECK(operand.IsStackSlot());
  return false;
}

template <typename Arg>
inline Register ToRegister(MaglevAssembler* masm,
                           MaglevAssembler::TemporaryRegisterScope* scratch,
                           Arg arg) {
  Register reg = scratch->AcquireScratch();
  masm->Move(reg, arg);
  return reg;
}
inline Register ToRegister(MaglevAssembler* masm,
                           MaglevAssembler::TemporaryRegisterScope* scratch,
                           Register reg) {
  return reg;
}
inline Register ToRegister(MaglevAssembler* masm,
                           MaglevAssembler::TemporaryRegisterScope* scratch,
                           const Input& input) {
  if (input.operand().IsConstant()) {
    Register reg = scratch->AcquireScratch();
    input.node()->LoadToRegister(masm, reg);
    return reg;
  }
  const compiler::AllocatedOperand& operand =
      compiler::AllocatedOperand::cast(input.operand());
  if (operand.IsRegister()) {
    return ToRegister(input);
  } else {
    DCHECK(operand.IsStackSlot());
    Register reg = scratch->AcquireScratch();
    masm->Move(reg, masm->ToMemOperand(input));
    return reg;
  }
}

template <typename... Args>
struct CountPushHelper;

template <>
struct CountPushHelper<> {
  static int Count() { return 0; }
};

template <typename Arg, typename... Args>
struct CountPushHelper<Arg, Args...> {
  static int Count(Arg arg, Args... args) {
    int arg_count = 1;
    if constexpr (is_iterator_range<Arg>::value) {
      arg_count = static_cast<int>(std::distance(arg.begin(), arg.end()));
    }
    return arg_count + CountPushHelper<Args...>::Count(args...);
  }
};

template <typename... Args>
struct PushAllHelper;

template <>
struct PushAllHelper<> {
  static void Push(MaglevAssembler* masm) {}
  static void PushReverse(MaglevAssembler* masm) {}
};

template <typename... Args>
inline void PushAll(MaglevAssembler* masm, Args... args) {
  PushAllHelper<Args...>::Push(masm, args...);
}

template <typename... Args>
inline void PushAllReverse(MaglevAssembler* masm, Args... args) {
  PushAllHelper<Args...>::PushReverse(masm, args...);
}

inline void PushInput(MaglevAssembler* masm, const Input& input) {
  if (input.operand().IsConstant()) {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    Register scratch = temps.AcquireScratch();
    input.node()->LoadToRegister(masm, scratch);
    masm->Push(scratch);
  } else {
    // TODO(leszeks): Consider special casing the value. (Toon: could possibly
    // be done through Input directly?)
    const compiler::AllocatedOperand& operand =
        compiler::AllocatedOperand::cast(input.operand());
    if (operand.IsRegister()) {
      masm->Push(operand.GetRegister());
    } else {
      DCHECK(operand.IsStackSlot());
      MaglevAssembler::TemporaryRegisterScope temps(masm);
      Register scratch = temps.AcquireScratch();
      masm->LoadWord(scratch, masm->GetStackSlot(operand));
      masm->Push(scratch);
    }
  }
}

template <typename T, typename... Args>
inline void PushIterator(MaglevAssembler* masm, base::iterator_range<T> range,
                         Args... args) {
  for (auto iter = range.begin(), end = range.end(); iter != end; ++iter) {
    masm->Push(*iter);
  }
  PushAllHelper<Args...>::Push(masm, args...);
}

template <typename T, typename... Args>
inline void PushIteratorReverse(MaglevAssembler* masm,
                                base::iterator_range<T> range, Args... args) {
  PushAllHelper<Args...>::PushReverse(masm, args...);
  for (auto iter = range.rbegin(), end = range.rend(); iter != end; ++iter) {
    masm->Push(*iter);
  }
}

template <typename... Args>
struct PushAllHelper<Input, Args...> {
  static void Push(MaglevAssembler* masm, const Input& arg, Args... args) {
    PushInput(masm, arg);
    PushAllHelper<Args...>::Push(masm, args...);
  }
  static void PushReverse(MaglevAssembler* masm, const Input& arg,
                          Args... args) {
    PushAllHelper<Args...>::PushReverse(masm, args...);
    PushInput(masm, arg);
  }
};
template <typename Arg, typename... Args>
struct PushAllHelper<Arg, Args...> {
  static void Push(MaglevAssembler* masm, Arg arg, Args... args) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIterator(masm, arg, args...);
    } else {
      masm->MacroAssembler::Push(arg);
      PushAllHelper<Args...>::Push(masm, args...);
    }
  }
  static void PushReverse(MaglevAssembler* masm, Arg arg, Args... args) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIteratorReverse(masm, arg, args...);
    } else {
      PushAllHelper<Args...>::PushReverse(masm, args...);
      masm->Push(arg);
    }
  }
};

}  // namespace detail

template <typename... T>
void MaglevAssembler::Push(T... vals) {
  detail::PushAll(this, vals...);
}

template <typename... T>
void MaglevAssembler::PushReverse(T... vals) {
  detail::PushAllReverse(this, vals...);
}

inline void MaglevAssembler::BindJumpTarget(Label* label) {
  MacroAssembler::BindJumpTarget(label);
}

inline void MaglevAssembler::BindBlock(BasicBlock* block) {
  if (block->is_start_block_of_switch_case()) {
    BindJumpTarget(block->label());
  } else {
    bind(block->label());
  }
}

inline Condition MaglevAssembler::CheckSmi(Register src) {
  Register cmp_flag = MaglevAssembler::GetFlagsRegister();
  // Pointers to heap objects have a 1 set for the bottom bit,
  // so cmp_flag is set to 0 if src is Smi.
  MacroAssembler::SmiTst(src, cmp_flag);
  return eq;
}

#ifdef V8_ENABLE_DEBUG_CODE
inline void MaglevAssembler::AssertMap(Register object) {
  if (!v8_flags.debug_code) return;
  ASM_CODE_COMMENT(this);
  AssertNotSmi(object, AbortReason::kOperandIsNotAMap);

  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register temp = temps.AcquireScratch();
  Label ConditionMet, Done;
  MacroAssembler::JumpIfObjectType(&Done, Condition::kEqual, object, MAP_TYPE,
                                   temp);
  Abort(AbortReason::kOperandIsNotAMap);
  bind(&Done);
}
#endif

inline void MaglevAssembler::SmiTagInt32AndSetFlags(Register dst,
                                                    Register src) {
  // FIXME check callsites and subsequent calls to Assert!
  ASM_CODE_COMMENT(this);
  static_assert(kSmiTag == 0);
  // NB: JumpIf expects the result in dedicated "flag" register
  Register overflow_flag = MaglevAssembler::GetFlagsRegister();
  if (SmiValuesAre31Bits()) {
    // Smi is shifted left by 1, so double incoming integer using 64- and 32-bit
    // addition operations and then compare the results to detect overflow. The
    // order does matter cuz in common way dst != src is NOT guarantied
    Add64(overflow_flag, src, src);
    Add32(dst, src, src);
    Sne(overflow_flag, overflow_flag, Operand(dst));
  } else {
    // Smi goes to upper 32
    slli(dst, src, 32);
    // no overflow happens (check!)
    Move(overflow_flag, zero_reg);
  }
}

inline void MaglevAssembler::CheckInt32IsSmi(Register maybeSmi, Label* fail,
                                             Register scratch) {
  DCHECK(!SmiValuesAre32Bits());
  // Smi is shifted left by 1
  MaglevAssembler::TemporaryRegisterScope temps(this);
  if (scratch == Register::no_reg()) {
    scratch = temps.AcquireScratch();
  }
  Register sum32 = scratch;
  Register sum64 = temps.AcquireScratch();
  Add32(sum32, maybeSmi, Operand(maybeSmi));
  Add64(sum64, maybeSmi, Operand(maybeSmi));
  // overflow happened if sum64 != sum32
  MacroAssembler::Branch(fail, ne, sum64, Operand(sum32));
}

inline void MaglevAssembler::SmiAddConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  if (value != 0) {
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register overflow = temps.AcquireScratch();
    Operand addend = Operand(Smi::FromInt(value));
    if (SmiValuesAre31Bits()) {
      Add64(overflow, src, addend);
      Add32(dst, src, addend);
      Sub64(overflow, dst, overflow);
      MacroAssembler::Branch(fail, ne, overflow, Operand(zero_reg), distance);
    } else {
      AddOverflow64(dst, src, addend, overflow);
      MacroAssembler::Branch(fail, lt, overflow, Operand(zero_reg), distance);
    }
  } else {
    Move(dst, src);
  }
}

inline void MaglevAssembler::SmiSubConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  if (value != 0) {
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register overflow = temps.AcquireScratch();
    Operand subtrahend = Operand(Smi::FromInt(value));
    if (SmiValuesAre31Bits()) {
      Sub64(overflow, src, subtrahend);
      Sub32(dst, src, subtrahend);
      Sub64(overflow, dst, overflow);
      MacroAssembler::Branch(fail, ne, overflow, Operand(zero_reg), distance);
    } else {
      SubOverflow64(dst, src, subtrahend, overflow);
      MacroAssembler::Branch(fail, lt, overflow, Operand(zero_reg), distance);
    }
  } else {
    Move(dst, src);
  }
}

inline void MaglevAssembler::MoveHeapNumber(Register dst, double value) {
  li(dst, Operand::EmbeddedNumber(value));
}

// Compare the object in a register to a value from the root list.
inline void MaglevAssembler::CompareRoot(const Register& obj, RootIndex index,
                                         ComparisonMode mode) {
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();
  MacroAssembler::CompareRoot(obj, index, aflag, mode);
}

inline void MaglevAssembler::CompareTaggedRoot(const Register& obj,
                                               RootIndex index) {
  constexpr Register cmp_result = MaglevAssembler::GetFlagsRegister();
  MacroAssembler::CompareTaggedRoot(obj, index, cmp_result);
}

inline void MaglevAssembler::CmpTagged(const Register& rs1,
                                       const Register& rs2) {
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();
  MacroAssembler::CmpTagged(aflag, rs1, rs2);
}

// Cmp and Assert are only used in maglev unittests, so to make them happy.
// It's only used with subsequent Assert kEqual,
// so pseudo flag should be 0 if rn equals imm
inline void MaglevAssembler::Cmp(const Register& rn, int imm) {
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();
  SubWord(aflag, rn, Operand(imm));
}

inline void MaglevAssembler::Assert(Condition cond, AbortReason reason) {
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();
  MacroAssembler::Assert(cond, reason, aflag, Operand(zero_reg));
}

inline Condition MaglevAssembler::IsRootConstant(Input input,
                                                 RootIndex root_index) {
  constexpr Register aflag = MaglevAssembler::GetFlagsRegister();

  if (input.operand().IsRegister()) {
    MacroAssembler::CompareRoot(ToRegister(input), root_index, aflag);
  } else {
    DCHECK(input.operand().IsStackSlot());
    MaglevAssembler::TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    LoadWord(scratch, ToMemOperand(input));
    MacroAssembler::CompareRoot(scratch, root_index, aflag);
  }
  return eq;
}

inline MemOperand MaglevAssembler::StackSlotOperand(StackSlot slot) {
  return MemOperand(fp, slot.index);
}

inline Register MaglevAssembler::GetFramePointer() { return fp; }

// TODO(Victorgomes): Unify this to use StackSlot struct.
inline MemOperand MaglevAssembler::GetStackSlot(
    const compiler::AllocatedOperand& operand) {
  return MemOperand(fp, GetFramePointerOffsetForStackSlot(operand));
}

inline MemOperand MaglevAssembler::ToMemOperand(
    const compiler::InstructionOperand& operand) {
  return GetStackSlot(compiler::AllocatedOperand::cast(operand));
}

inline MemOperand MaglevAssembler::ToMemOperand(const ValueLocation& location) {
  return ToMemOperand(location.operand());
}

inline void MaglevAssembler::BuildTypedArrayDataPointer(Register data_pointer,
                                                        Register object) {
  DCHECK_NE(data_pointer, object);
  LoadExternalPointerField(
      data_pointer,
      FieldMemOperand(object, JSTypedArray::kExternalPointerOffset));
  if (JSTypedArray::kMaxSizeInHeap == 0) return;
  MaglevAssembler::TemporaryRegisterScope scope(this);
  Register base = scope.AcquireScratch();
  if (COMPRESS_POINTERS_BOOL) {
    Load32U(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  } else {
    LoadWord(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  }
  Add64(data_pointer, data_pointer, base);
}

inline MemOperand MaglevAssembler::TypedArrayElementOperand(
    Register data_pointer, Register index, int element_size) {
  const int shift = ShiftFromScale(element_size);
  if (shift == 0) {
    AddWord(data_pointer, data_pointer, index);
  } else {
    CalcScaledAddress(data_pointer, data_pointer, index, shift);
  }
  return MemOperand(data_pointer);
}

inline MemOperand MaglevAssembler::DataViewElementOperand(Register data_pointer,
                                                          Register index) {
  Add64(data_pointer, data_pointer,
        index);  // FIXME: should we check for COMPRESSED PTRS enabled here ?
  return MemOperand(data_pointer);
}

inline void MaglevAssembler::LoadTaggedFieldByIndex(Register result,
                                                    Register object,
                                                    Register index, int scale,
                                                    int offset) {
  const int shift = ShiftFromScale(scale);
  if (shift == 0) {
    AddWord(result, object, index);
  } else {
    CalcScaledAddress(result, object, index, shift);
  }
  LoadTaggedField(result, FieldMemOperand(result, offset));
}

inline void MaglevAssembler::LoadBoundedSizeFromObject(Register result,
                                                       Register object,
                                                       int offset) {
  Move(result, FieldMemOperand(object, offset));
#ifdef V8_ENABLE_SANDBOX
  SrlWord(result, result, Operand(kBoundedSizeShift));
#endif  // V8_ENABLE_SANDBOX
}

inline void MaglevAssembler::LoadExternalPointerField(Register result,
                                                      MemOperand operand) {
#ifdef V8_ENABLE_SANDBOX
  LoadSandboxedPointerField(result, operand);
#else
  Move(result, operand);
#endif
}

void MaglevAssembler::LoadFixedArrayElement(Register result, Register array,
                                            Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  LoadTaggedFieldByIndex(result, array, index, kTaggedSize,
                         OFFSET_OF_DATA_START(FixedArray));
}

inline void MaglevAssembler::LoadTaggedFieldWithoutDecompressing(
    Register result, Register object, int offset) {
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(object, offset));
}

void MaglevAssembler::LoadFixedArrayElementWithoutDecompressing(
    Register result, Register array, Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_ARRAY_TYPE, AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  CalcScaledAddress(result, array, index, kTaggedSizeLog2);
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(result, OFFSET_OF_DATA_START(FixedArray)));
}

void MaglevAssembler::LoadFixedDoubleArrayElement(DoubleRegister result,
                                                  Register array,
                                                  Register index) {
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_DOUBLE_ARRAY_TYPE,
                     AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CalcScaledAddress(scratch, array, index, kDoubleSizeLog2);
  LoadDouble(result,
             FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::StoreFixedDoubleArrayElement(
    Register array, Register index, DoubleRegister value) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CalcScaledAddress(scratch, array, index, kDoubleSizeLog2);
  StoreDouble(value,
              FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::LoadSignedField(Register result,
                                             MemOperand operand, int size) {
  if (size == 1) {
    Lb(result, operand);
  } else if (size == 2) {
    Lh(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    Lw(result, operand);
  }
}

inline void MaglevAssembler::LoadUnsignedField(Register result,
                                               MemOperand operand, int size) {
  if (size == 1) {
    Lbu(result, operand);
  } else if (size == 2) {
    Lhu(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    Lwu(result, operand);
  }
}

inline void MaglevAssembler::SetSlotAddressForTaggedField(Register slot_reg,
                                                          Register object,
                                                          int offset) {
  Add64(slot_reg, object, offset - kHeapObjectTag);
}

inline void MaglevAssembler::SetSlotAddressForFixedArrayElement(
    Register slot_reg, Register object, Register index) {
  Add64(slot_reg, object, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  CalcScaledAddress(slot_reg, slot_reg, index, kTaggedSizeLog2);
}

inline void MaglevAssembler::StoreTaggedFieldNoWriteBarrier(Register object,
                                                            int offset,
                                                            Register value) {
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreFixedArrayElementNoWriteBarrier(
    Register array, Register index, Register value) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CalcScaledAddress(scratch, array, index, kTaggedSizeLog2);
  MacroAssembler::StoreTaggedField(
      value, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::StoreTaggedSignedField(Register object, int offset,
                                                    Register value) {
  AssertSmi(value);
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreTaggedSignedField(Register object, int offset,
                                                    Tagged<Smi> value) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Move(scratch, value);
  MacroAssembler::StoreTaggedField(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreInt32Field(Register object, int offset,
                                             int32_t value) {
  if (value == 0) {
    Sw(zero_reg, FieldMemOperand(object, offset));
    return;
  }
  MaglevAssembler::TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  Move(scratch, value);
  Sw(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreField(MemOperand operand, Register value,
                                        int size) {
  DCHECK(size == 1 || size == 2 || size == 4);
  if (size == 1) {
    Sb(value, operand);
  } else if (size == 2) {
    Sh(value, operand);
  } else {
    DCHECK_EQ(size, 4);
    Sw(value, operand);
  }
}

inline void MaglevAssembler::ReverseByteOrder(Register value, int size) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  if (size == 2) {
    ByteSwap(value, value, 4, scratch);
    srai(value, value, 16);
  } else if (size == 4) {
    ByteSwap(value, value, 4, scratch);
  } else {
    DCHECK_EQ(size, 1);
  }
}

inline void MaglevAssembler::IncrementInt32(Register reg) {
  Add32(reg, reg, Operand(1));
}

inline void MaglevAssembler::DecrementInt32(Register reg) {
  Sub32(reg, reg, Operand(1));
}

inline void MaglevAssembler::AddInt32(Register reg, int amount) {
  Add32(reg, reg, Operand(amount));
}

inline void MaglevAssembler::AndInt32(Register reg, int mask) {
  // check if size of immediate exceeds 32 bits
  if constexpr (sizeof(intptr_t) > sizeof(mask)) {
    // set the upper bits of the immediate and so make sure that AND operation
    // won't touch the upper part of target register
    static constexpr intptr_t lsb_mask = 0xFFFFFFFF;
    And(reg, reg, Operand(~lsb_mask | mask));
  } else {
    And(reg, reg, Operand(mask));
  }
}

inline void MaglevAssembler::OrInt32(Register reg, int mask) {
  // OR won't touch the upper part of target register
  Or(reg, reg, Operand(mask));
}

inline void MaglevAssembler::ShiftLeft(Register reg, int amount) {
  Sll32(reg, reg, Operand(amount));
}

inline void MaglevAssembler::IncrementAddress(Register reg, int32_t delta) {
  Add64(reg, reg, Operand(delta));
}

inline void MaglevAssembler::LoadAddress(Register dst, MemOperand location) {
  DCHECK(location.is_reg());
  Add64(dst, location.rm(), location.offset());
}

inline void MaglevAssembler::Call(Label* target) {
  MacroAssembler::Call(target);
}

inline void MaglevAssembler::EmitEnterExitFrame(int extra_slots,
                                                StackFrame::Type frame_type,
                                                Register c_function,
                                                Register scratch) {
  EnterExitFrame(scratch, extra_slots, frame_type);
}

inline void MaglevAssembler::Move(StackSlot dst, Register src) {
  StoreWord(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(StackSlot dst, DoubleRegister src) {
  StoreDouble(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(Register dst, StackSlot src) {
  LoadWord(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(DoubleRegister dst, StackSlot src) {
  LoadDouble(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(MemOperand dst, Register src) {
  StoreWord(src, dst);
}
inline void MaglevAssembler::Move(Register dst, MemOperand src) {
  LoadWord(dst, src);
}
inline void MaglevAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  MoveDouble(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Tagged<Smi> src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, ExternalReference src) {
  li(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Register src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Tagged<TaggedIndex> i) {
  li(dst, Operand(i.ptr()));
}
inline void MaglevAssembler::Move(Register dst, int32_t i) {
  li(dst, Operand(i));
}
inline void MaglevAssembler::Move(Register dst, uint32_t i) {
  li(dst, Operand(i));
}
inline void MaglevAssembler::Move(DoubleRegister dst, double n) {
  LoadFPRImmediate(dst, n);
}
inline void MaglevAssembler::Move(DoubleRegister dst, Float64 n) {
  LoadFPRImmediate(dst, n.get_scalar());
}
inline void MaglevAssembler::Move(Register dst, Handle<HeapObject> obj) {
  li(dst, Operand(obj));
}
void MaglevAssembler::MoveTagged(Register dst, Handle<HeapObject> obj) {
#ifdef V8_COMPRESS_POINTERS
  li(dst, obj, RelocInfo::COMPRESSED_EMBEDDED_OBJECT);
#else
  ASM_CODE_COMMENT_STRING(this, "MaglevAsm::MoveTagged");
  Move(dst, obj);
#endif
}

inline void MaglevAssembler::LoadFloat32(DoubleRegister dst, MemOperand src) {
  LoadFloat(dst, src);
  // Convert Float32 to double(Float64)
  fcvt_d_s(dst, dst);
}
inline void MaglevAssembler::StoreFloat32(MemOperand dst, DoubleRegister src) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireScratchDouble();
  // Convert double(Float64) to Float32
  fcvt_s_d(scratch, src);
  StoreFloat(scratch, dst);
}
inline void MaglevAssembler::LoadFloat64(DoubleRegister dst, MemOperand src) {
  LoadDouble(dst, src);
}
inline void MaglevAssembler::StoreFloat64(MemOperand dst, DoubleRegister src) {
  StoreDouble(src, dst);
}

inline void MaglevAssembler::LoadUnalignedFloat64(DoubleRegister dst,
                                                  Register base,
                                                  Register index) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register address = temps.AcquireScratch();
  Add64(address, base, index);
  ULoadDouble(dst, MemOperand(address), scratch);
}
inline void MaglevAssembler::LoadUnalignedFloat64AndReverseByteOrder(
    DoubleRegister dst, Register base, Register index) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register address = temps.AcquireScratch();
  Add64(address, base, index);
  Uld(scratch, MemOperand(address));
  ByteSwap(scratch, scratch, 8, address);  // reuse address as scratch register
  MacroAssembler::Move(dst, scratch);
}
inline void MaglevAssembler::StoreUnalignedFloat64(Register base,
                                                   Register index,
                                                   DoubleRegister src) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register address = temps.AcquireScratch();
  Add64(address, base, index);
  UStoreDouble(src, MemOperand(address), scratch);
}
inline void MaglevAssembler::ReverseByteOrderAndStoreUnalignedFloat64(
    Register base, Register index, DoubleRegister src) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register address = temps.AcquireScratch();
  MacroAssembler::Move(scratch, src);
  ByteSwap(scratch, scratch, 8, address);  // reuse address as scratch register
  Add64(address, base, index);
  Usd(scratch, MemOperand(address));
}

inline void MaglevAssembler::SignExtend32To64Bits(Register dst, Register src) {
  SignExtendWord(dst, src);
}

inline void MaglevAssembler::NegateInt32(Register val) {
  SignExtendWord(val, val);
  Neg(val, val);
}

inline void MaglevAssembler::ToUint8Clamped(Register result,
                                            DoubleRegister value, Label* min,
                                            Label* max, Label* done) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register scratch2 = temps.AcquireScratch();
  DoubleRegister ftmp1 = temps.AcquireScratchDouble();
  DCHECK(ftmp1 != value);

  // if value is NOT in (0.0, 255.0), then fallback to min or max.
  fclass_d(scratch, value);
  constexpr int32_t nan_neg_mask =
      (kNegativeInfinity | kNegativeNormalNumber | kNegativeSubnormalNumber |
       kNegativeZero | kPositiveZero | kSignalingNaN | kQuietNaN);
  constexpr int32_t pos_inf_mask = kPositiveInfinity;
  And(scratch2, scratch, Operand(nan_neg_mask));
  MacroAssembler::Branch(min,  // value is NaN or value <= 0.0
                         not_equal, scratch2, Operand(zero_reg));
  And(scratch2, scratch, Operand(pos_inf_mask));
  MacroAssembler::Branch(max,  // value is +Infinity
                         not_equal, scratch2, Operand(zero_reg));
  // 255.0 is 0x406F_E000_0000_0000 in IEEE-754 floating point format
  Add32
```