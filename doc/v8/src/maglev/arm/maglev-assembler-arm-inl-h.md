Response:
The user wants a summary of the C++ header file `v8/src/maglev/arm/maglev-assembler-arm-inl.h`.

Here's a breakdown of the request:

1. **List its functionalities**:  I need to go through the code and describe what each part does.
2. **Check for `.tq` extension**:  The file ends in `.h`, not `.tq`, so it's not a Torque file. I should explicitly state this.
3. **Relate to Javascript**: I need to identify if any functionality in this file directly corresponds to Javascript features. If so, I must provide Javascript examples. This file deals with low-level assembly generation, so the connection to Javascript will be more about *how* certain Javascript operations are implemented under the hood.
4. **Code logic and examples**: If there are specific logical code snippets, I should provide hypothetical inputs and their corresponding outputs. This is more relevant for functions that perform some transformation or check.
5. **Common programming errors**: If the code relates to areas where developers commonly make mistakes, I need to provide examples of these errors.
6. **Part 1 of 2**: This is the first part, so the summary should focus on the functionalities present in this specific code snippet.
7. **Summarize its functionalities**:  Provide a high-level overview of what this code achieves.

**Plan:**

1. Read through the code, function by function, and understand its purpose.
2. Identify the main categories of functionality (e.g., register management, memory access, arithmetic operations, control flow).
3. Determine if and how these functionalities relate to Javascript concepts.
4. For interesting code snippets, create simple input/output examples.
5. Think about common developer errors that might relate to the functionalities (though this is low-level, so it might be less direct).
6. Synthesize a summary based on the identified functionalities.
这是一个V8 Maglev编译器的ARM架构后端汇编器内联头文件。它为在ARM架构上生成机器码提供了便捷的接口和辅助函数。以下是其主要功能的归纳：

**核心功能：提供用于生成ARM汇编指令的C++接口，用于V8的Maglev优化编译器。**

**详细功能列表：**

1. **条件码辅助函数:**
    *   `ConditionForFloat64(Operation operation)`:  根据操作类型返回用于浮点数比较的条件码。
    *   `ConditionForNaN()`: 返回用于检查NaN（非数字）的条件码。

2. **移位计算:**
    *   `ShiftFromScale(int n)`:  根据比例因子（1, 2, 4, 8）计算移位值，这通常用于计算数组元素的偏移量。

3. **临时寄存器管理:**
    *   `MaglevAssembler::TemporaryRegisterScope`:  一个RAII（资源获取即初始化）类，用于自动管理临时寄存器的分配和释放。它允许安全地获取和释放通用寄存器和浮点寄存器。
    *   `AcquireScratch()`: 获取一个临时的通用寄存器。
    *   `AcquireScratchDouble()`: 获取一个临时的双精度浮点寄存器。
    *   `IncludeScratch()`: 将一个寄存器添加到可用的临时寄存器列表中。
    *   `CopyForDefer()`: 复制当前临时寄存器作用域的状态，用于延迟代码生成。
    *   `ResetToDefaultImpl()`: 将临时寄存器作用域重置为默认状态。

4. **Map比较:**
    *   `MapCompare`:  一个辅助类，用于比较对象的Map（V8中用于描述对象类型和布局的结构）。
    *   `Generate(Handle<Map> map, Condition cond, Label* if_true, Label::Distance distance)`: 生成代码，检查对象的Map是否与给定的Map相等，如果满足条件则跳转。
    *   `GetMap()`: 获取存储对象Map的寄存器。
    *   `TemporaryCount(size_t map_count)`: 返回执行Map比较所需的临时寄存器数量。

5. **栈操作辅助函数:**
    *   `Push(...)`: 将一个或多个值（寄存器、立即数、内存地址等）压入栈中。提供了多种重载以处理不同类型的值，包括 `Input`（Maglev节点的操作数）。
    *   `PushReverse(...)`: 以相反的顺序将值压入栈中。

6. **代码绑定:**
    *   `BindJumpTarget(Label* label)`: 将标签绑定到当前代码位置。
    *   `BindBlock(BasicBlock* block)`: 将基本块的标签绑定到当前代码位置。

7. **Smi（小整数）操作:**
    *   `SmiTagInt32AndSetFlags(Register dst, Register src)`: 将32位整数标记为Smi，并设置条件标志。
    *   `CheckInt32IsSmi(Register obj, Label* fail, Register scratch)`: 检查一个值是否是Smi。
    *   `SmiAddConstant(Register dst, Register src, int value, Label* fail, Label::Distance distance)`: 将一个常量加到Smi上。
    *   `SmiSubConstant(Register dst, Register src, int value, Label* fail, Label::Distance distance)`: 从Smi中减去一个常量。

8. **堆数字操作:**
    *   `MoveHeapNumber(Register dst, double value)`: 将一个双精度浮点数加载到寄存器中（作为堆数字）。

9. **根对象比较:**
    *   `IsRootConstant(Input input, RootIndex root_index)`:  比较一个输入操作数是否是指定的根对象。

10. **内存操作:**
    *   `StackSlotOperand(StackSlot slot)`:  计算栈槽的内存操作数。
    *   `GetFramePointer()`: 获取帧指针寄存器。
    *   `GetStackSlot(const compiler::AllocatedOperand& operand)`: 获取分配的操作数的栈槽内存操作数。
    *   `ToMemOperand(...)`: 将操作数或值位置转换为内存操作数。
    *   `BuildTypedArrayDataPointer(Register data_pointer, Register object)`: 计算类型化数组的数据指针。
    *   `TypedArrayElementOperand(Register data_pointer, Register index, int element_size)`: 计算类型化数组元素的内存操作数。
    *   `DataViewElementOperand(Register data_pointer, Register index)`: 计算DataView元素的内存操作数。
    *   `LoadTaggedFieldByIndex(...)`:  根据索引加载对象的标记字段。
    *   `LoadBoundedSizeFromObject(...)`: 加载对象中指定偏移量的有界大小值。
    *   `LoadExternalPointerField(...)`: 加载外部指针字段。
    *   `LoadFixedArrayElement(...)`: 加载固定数组的元素。
    *   `LoadFixedArrayElementWithoutDecompressing(...)`: 加载固定数组元素，不进行解压缩（ARM架构上没有压缩模式）。
    *   `LoadFixedDoubleArrayElement(...)`: 加载固定双精度浮点数数组的元素。
    *   `StoreFixedDoubleArrayElement(...)`: 存储固定双精度浮点数数组的元素。
    *   `LoadSignedField(...)`: 加载有符号字段。
    *   `LoadUnsignedField(...)`: 加载无符号字段。
    *   `SetSlotAddressForTaggedField(...)`: 计算标记字段的地址。
    *   `SetSlotAddressForFixedArrayElement(...)`: 计算固定数组元素的地址。
    *   `StoreTaggedFieldNoWriteBarrier(...)`: 存储标记字段，不使用写屏障。
    *   `StoreFixedArrayElementNoWriteBarrier(...)`: 存储固定数组元素，不使用写屏障。
    *   `StoreTaggedSignedField(...)`: 存储标记的有符号字段。
    *   `StoreInt32Field(...)`: 存储32位整数字段。
    *   `StoreField(...)`: 存储指定大小的字段。
    *   `ReverseByteOrder(...)`: 反转字节序。

11. **算术和逻辑运算:**
    *   `IncrementInt32(Register reg)`: 递增32位整数寄存器。
    *   `DecrementInt32(Register reg)`: 递减32位整数寄存器。
    *   `AddInt32(Register reg, int amount)`: 将一个常量加到32位整数寄存器。
    *   `AndInt32(Register reg, int mask)`: 对32位整数寄存器执行按位与操作。
    *   `OrInt32(Register reg, int mask)`: 对32位整数寄存器执行按位或操作。
    *   `ShiftLeft(Register reg, int amount)`: 对寄存器执行左移操作。
    *   `NegateInt32(Register val)`: 取反32位整数寄存器。

12. **地址操作:**
    *   `IncrementAddress(Register reg, int32_t delta)`: 增加地址寄存器的值。
    *   `LoadAddress(Register dst, MemOperand location)`: 将内存地址加载到寄存器。

13. **控制流:**
    *   `Call(Label* target)`: 调用指定标签处的代码。
    *   `Jump(Label* target, Label::Distance)`: 跳转到指定标签。
    *   `JumpToDeopt(Label* target)`: 跳转到反优化代码。
    *   `JumpIf(Condition cond, Label* target, Label::Distance)`: 如果满足条件则跳转。
    *   `JumpIfRoot(...)`: 如果寄存器中的值是指定的根对象则跳转。
    *   `JumpIfNotRoot(...)`: 如果寄存器中的值不是指定的根对象则跳转。
    *   `EmitEagerDeoptStress(Label* target)`: 用于压力测试，触发立即反优化。

14. **帧操作:**
    *   `EmitEnterExitFrame(...)`: 生成进入和退出函数帧的代码。

15. **数据移动:**
    *   `Move(...)`:  在寄存器、栈槽和内存之间移动数据。提供了多种重载以处理不同数据类型。
    *   `LoadFloat32(...)`, `StoreFloat32(...)`, `LoadFloat64(...)`, `StoreFloat64(...)`: 加载和存储单精度和双精度浮点数。
    *   `LoadUnalignedFloat64(...)`, `StoreUnalignedFloat64(...)`: 加载和存储未对齐的双精度浮点数。
    *   `LoadUnalignedFloat64AndReverseByteOrder(...)`, `ReverseByteOrderAndStoreUnalignedFloat64(...)`: 加载和存储未对齐且字节序反转的双精度浮点数。
    *   `SignExtend32To64Bits(Register dst, Register src)`: 将32位有符号数符号扩展为64位（在ARM上此操作可能为空，因为没有64位通用寄存器直接对应）。

16. **类型转换:**
    *   `ToUint8Clamped(...)`: 将浮点数转换为0到255之间的无符号8位整数，超出范围的值会被截断到边界。

17. **反优化支持:**
    *   `DeoptIfBufferDetached(...)`: 如果ArrayBuffer被分离则触发反优化。

18. **对象类型检查和断言:**
    *   `IsCallableAndNotUndetectable(...)`: 检查Map指示的对象是否可调用且不是不可检测的。
    *   `IsNotCallableNorUndetactable(...)`: 检查Map指示的对象是否既不可调用也不是不可检测的。
    *   `LoadInstanceType(...)`: 加载对象的实例类型。
    *   `JumpIfObjectType(...)`, `JumpIfNotObjectType(...)`:  根据对象类型跳转。
    *   `AssertObjectType(...)`: 断言对象是指定的类型，如果不是则中止执行。
    *   `BranchOnObjectType(...)`: 根据对象类型进行分支。
    *   `JumpIfObjectTypeInRange(...)`, `JumpIfObjectTypeNotInRange(...)`: 检查对象类型是否在指定范围内。
    *   `AssertObjectTypeInRange(...)`: 断言对象类型在指定范围内。
    *   `BranchOnObjectTypeInRange(...)`: 根据对象类型是否在指定范围内进行分支。
    *   `JumpIfJSAnyIsNotPrimitive(...)`: 如果对象不是原始类型则跳转。
    *   `CompareMapWithRoot(...)`: 将对象的Map与根对象进行比较。
    *   `CompareInstanceType(...)`: 将Map的实例类型与给定类型进行比较。
    *   `CompareInstanceTypeRange(...)`: 比较Map的实例类型是否在给定范围内。

19. **浮点数比较:**
    *   `CompareFloat64AndJumpIf(...)`: 比较两个双精度浮点数，如果满足条件则跳转。处理NaN的情况。
    *   `CompareFloat64AndBranch(...)`: 比较两个双精度浮点数，并根据结果跳转到不同的基本块。处理NaN的情况。

20. **C函数调用准备:**
    *   `PrepareCallCFunction(...)`:  为调用C函数做准备，设置参数寄存器等。

21. **自调用:**
    *   `CallSelf()`: 调用当前正在生成的代码的入口点，用于尾调用优化等。

**关于文件扩展名和Torque:**

`v8/src/maglev/arm/maglev-assembler-arm-inl.h` 的文件扩展名是 `.h`，这是一个C++头文件。 如果文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于生成 V8 代码的领域特定语言，通常用于生成一些样板代码或者与类型相关的操作。这个文件不是 Torque 文件。

**与 Javascript 的关系：**

这个文件中的代码直接用于实现 Javascript 的各种功能。当 V8 的 Maglev 编译器优化 Javascript 代码时，它会将 Javascript 代码转换成这种底层的 ARM 汇编指令。例如：

*   **算术运算 (+, -, *, /):**  `SmiAddConstant`, `SmiSubConstant`, 浮点数加载、存储和比较等函数会被用于实现 Javascript 中的加减乘除运算。
*   **对象属性访问 (. , []):** `LoadTaggedFieldByIndex` 等函数用于加载对象的属性。 `MapCompare` 用于检查对象的类型是否符合预期。
*   **数组操作:**  `LoadFixedArrayElement`, `StoreFixedDoubleArrayElement`, `BuildTypedArrayDataPointer` 等函数用于处理 Javascript 数组和类型化数组。
*   **函数调用:** `Call` 和 `EmitEnterExitFrame` 用于实现 Javascript 函数的调用和栈帧管理。
*   **类型检查 (typeof, instanceof):**  `JumpIfObjectType`, `CompareMapWithRoot` 等函数用于实现 Javascript 中的类型检查操作。

**Javascript 示例：**

```javascript
function add(a, b) {
  return a + b;
}

let arr = [1.1, 2.2, 3.3];
let sum = 0;
for (let i = 0; i < arr.length; i++) {
  sum += arr[i];
}

let obj = { x: 10 };
console.log(obj.x);

function isNumber(val) {
  return typeof val === 'number';
}
```

当 Maglev 编译优化上述 Javascript 代码时，`maglev-assembler-arm-inl.h` 中定义的函数会被用来生成对应的 ARM 汇编指令，例如：

*   `add(a, b)` 中的 `+` 运算可能会使用 `SmiAddConstant` (如果 a 和 b 是 Smi) 或浮点数加法指令。
*   访问 `arr[i]` 可能会使用 `LoadFixedDoubleArrayElement`。
*   访问 `obj.x` 可能会使用 `LoadTaggedFieldByIndex`。
*   `typeof val === 'number'` 可能会使用 `CompareInstanceTypeRange` 来检查 `val` 的类型是否在数字类型的范围内。

**代码逻辑推理示例：**

**假设输入：**

*   `MaglevAssembler* masm`: 一个 `MaglevAssembler` 实例。
*   `Register dst`: 目标寄存器，例如 `r0`。
*   `Register src`: 源寄存器，例如 `r1`，其值为 Smi(5)。
*   `int value`: 常量值 3。
*   `Label* fail`: 一个标签，如果加法溢出则跳转到这里。

**代码片段：**

```c++
inline void MaglevAssembler::SmiAddConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  static_assert(!SmiValuesAre32Bits());
  AssertSmi(src);
  if (value != 0) {
    add(dst, src, Operand(Smi::FromInt(value)), SetCC);
    JumpIf(kOverflow, fail, distance);
  } else {
    Move(dst, src);
  }
}
```

**预期输出：**

如果调用 `masm->SmiAddConstant(r0, r1, 3, fail_label);`，并且 `r1` 中是 Smi(5)：

1. `value` 是 3，不等于 0，所以会执行 `add` 指令。
2. 生成的汇编指令可能是 `adds r0, r1, #6` (因为 3 被编码为 Smi 是 6)。
3. 如果加法没有溢出（5 + 3 = 8，可以表示为 Smi），则程序继续执行，`r0` 的值将变为 Smi(8)。
4. 如果加法溢出，则跳转到 `fail_label`。

**用户常见的编程错误（不直接在这个文件中体现，而是使用此汇编器的开发者可能犯的错误）：**

1. **不正确的寄存器分配:**  手动分配寄存器而没有正确跟踪其使用情况，可能导致寄存器冲突，数据被意外覆盖。 `TemporaryRegisterScope` 的使用可以帮助避免这种情况。
2. **错误的内存访问:**  计算内存地址时出错，例如错误的偏移量或索引，可能导致程序崩溃或数据损坏。
3. **忘记处理边界情况:** 例如，在数组访问前没有检查索引是否越界。虽然汇编器本身不负责这些检查，但生成的汇编代码需要处理这些情况，开发者可能会忘记生成相应的检查代码。
4. **不正确的类型假设:**  假设某个对象一定是某种类型，而没有进行类型检查，导致对对象进行了错误的操作。例如，假设一个值是 Smi 并直接进行 Smi 操作，但实际上它可能是一个 HeapObject。
5. **忘记写屏障:** 在存储对象引用时，如果没有正确使用写屏障，可能会导致垃圾回收器无法正确追踪对象，从而引发内存泄漏或悬 dangling 指针。  虽然 `StoreTaggedFieldNoWriteBarrier` 存在，但通常应该使用包含写屏障的版本。

这是 `v8/src/maglev/arm/maglev-assembler-arm-inl.h` 文件（第1部分）的功能归纳。它提供了一组用于在ARM架构上生成机器码的基础工具和抽象，是 Maglev 编译器后端的核心组成部分。

Prompt: 
```
这是目录为v8/src/maglev/arm/maglev-assembler-arm-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/arm/maglev-assembler-arm-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_ARM_MAGLEV_ASSEMBLER_ARM_INL_H_
#define V8_MAGLEV_ARM_MAGLEV_ASSEMBLER_ARM_INL_H_

#include "src/base/numbers/double.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/common/globals.h"
#include "src/compiler/compilation-dependencies.h"
#include "src/maglev/maglev-assembler.h"
#include "src/maglev/maglev-basic-block.h"
#include "src/maglev/maglev-code-gen-state.h"

namespace v8 {
namespace internal {
namespace maglev {

constexpr Condition ConditionForFloat64(Operation operation) {
  return ConditionFor(operation);
}

constexpr Condition ConditionForNaN() { return vs; }

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

class MaglevAssembler::TemporaryRegisterScope
    : public TemporaryRegisterScopeBase<TemporaryRegisterScope> {
  using Base = TemporaryRegisterScopeBase<TemporaryRegisterScope>;

 public:
  struct SavedData : public Base::SavedData {
    RegList available_scratch_;
    VfpRegList available_fp_scratch_;
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
    scratch_scope_.SetAvailableVfp(saved_data.available_fp_scratch_);
  }

  Register AcquireScratch() {
    Register reg = scratch_scope_.Acquire();
    CHECK(!available_.has(reg));
    return reg;
  }
  DoubleRegister AcquireScratchDouble() {
    DoubleRegister reg = scratch_scope_.AcquireD();
    CHECK(!available_double_.has(reg));
    return reg;
  }
  void IncludeScratch(Register reg) { scratch_scope_.Include(reg); }

  SavedData CopyForDefer() {
    return SavedData{
        CopyForDeferBase(),
        scratch_scope_.Available(),
        scratch_scope_.AvailableVfp(),
    };
  }

  void ResetToDefaultImpl() {
    scratch_scope_.SetAvailable(Assembler::DefaultTmpList() |
                                kMaglevExtraScratchRegister);
    scratch_scope_.SetAvailableVfp(Assembler::DefaultFPTmpList());
  }

 private:
  UseScratchRegisterScope scratch_scope_;
};

inline MapCompare::MapCompare(MaglevAssembler* masm, Register object,
                              size_t map_count)
    : masm_(masm), object_(object), map_count_(map_count) {
  map_ = masm_->scratch_register_scope()->Acquire();
  masm_->LoadMap(map_, object_);
  USE(map_count_);
}

void MapCompare::Generate(Handle<Map> map, Condition cond, Label* if_true,
                          Label::Distance distance) {
  MaglevAssembler::TemporaryRegisterScope temps(masm_);
  Register temp = temps.AcquireScratch();
  masm_->Move(temp, map);
  masm_->cmp(map_, temp);
  masm_->JumpIf(cond, if_true, distance);
}

Register MapCompare::GetMap() { return map_; }

int MapCompare::TemporaryCount(size_t map_count) { return 1; }

namespace detail {

template <typename... Args>
struct PushAllHelper;

template <>
struct PushAllHelper<> {
  static void Push(MaglevAssembler* masm) {}
  static void PushReverse(MaglevAssembler* masm) {}
};

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
      masm->ldr(scratch, masm->GetStackSlot(operand));
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
  detail::PushAllHelper<T...>::Push(this, vals...);
}

template <typename... T>
void MaglevAssembler::PushReverse(T... vals) {
  detail::PushAllHelper<T...>::PushReverse(this, vals...);
}

inline void MaglevAssembler::BindJumpTarget(Label* label) { bind(label); }

inline void MaglevAssembler::BindBlock(BasicBlock* block) {
  bind(block->label());
}

inline void MaglevAssembler::SmiTagInt32AndSetFlags(Register dst,
                                                    Register src) {
  add(dst, src, src, SetCC);
}

inline void MaglevAssembler::CheckInt32IsSmi(Register obj, Label* fail,
                                             Register scratch) {
  static_assert(!SmiValuesAre32Bits());

  TemporaryRegisterScope temps(this);
  if (scratch == Register::no_reg()) {
    scratch = temps.AcquireScratch();
  }
  add(scratch, obj, obj, SetCC);
  JumpIf(kOverflow, fail);
}

inline void MaglevAssembler::SmiAddConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  static_assert(!SmiValuesAre32Bits());
  AssertSmi(src);
  if (value != 0) {
    add(dst, src, Operand(Smi::FromInt(value)), SetCC);
    JumpIf(kOverflow, fail, distance);
  } else {
    Move(dst, src);
  }
}

inline void MaglevAssembler::SmiSubConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  static_assert(!SmiValuesAre32Bits());
  AssertSmi(src);
  if (value != 0) {
    sub(dst, src, Operand(Smi::FromInt(value)), SetCC);
    JumpIf(kOverflow, fail, distance);
  } else {
    Move(dst, src);
  }
}

inline void MaglevAssembler::MoveHeapNumber(Register dst, double value) {
  mov(dst, Operand::EmbeddedNumber(value));
}

inline Condition MaglevAssembler::IsRootConstant(Input input,
                                                 RootIndex root_index) {
  if (input.operand().IsRegister()) {
    CompareRoot(ToRegister(input), root_index);
  } else {
    DCHECK(input.operand().IsStackSlot());
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    ldr(scratch, ToMemOperand(input));
    CompareRoot(scratch, root_index);
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
  ldr(data_pointer,
      FieldMemOperand(object, JSTypedArray::kExternalPointerOffset));
  if (JSTypedArray::kMaxSizeInHeap == 0) return;
  TemporaryRegisterScope temps(this);
  Register base = temps.AcquireScratch();
  ldr(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  add(data_pointer, data_pointer, base);
}

inline MemOperand MaglevAssembler::TypedArrayElementOperand(
    Register data_pointer, Register index, int element_size) {
  add(data_pointer, data_pointer,
      Operand(index, LSL, ShiftFromScale(element_size)));
  return MemOperand(data_pointer);
}

inline MemOperand MaglevAssembler::DataViewElementOperand(Register data_pointer,
                                                          Register index) {
  return MemOperand(data_pointer, index);
}

inline void MaglevAssembler::LoadTaggedFieldByIndex(Register result,
                                                    Register object,
                                                    Register index, int scale,
                                                    int offset) {
  add(result, object, Operand(index, LSL, ShiftFromScale(scale)));
  MacroAssembler::LoadTaggedField(result, FieldMemOperand(result, offset));
}

inline void MaglevAssembler::LoadBoundedSizeFromObject(Register result,
                                                       Register object,
                                                       int offset) {
  Move(result, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::LoadExternalPointerField(Register result,
                                                      MemOperand operand) {
  Move(result, operand);
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

void MaglevAssembler::LoadFixedArrayElementWithoutDecompressing(
    Register result, Register array, Register index) {
  // No compression mode on arm.
  LoadFixedArrayElement(result, array, index);
}

void MaglevAssembler::LoadFixedDoubleArrayElement(DoubleRegister result,
                                                  Register array,
                                                  Register index) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_DOUBLE_ARRAY_TYPE,
                     AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  add(scratch, array, Operand(index, LSL, kDoubleSizeLog2));
  vldr(result, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::StoreFixedDoubleArrayElement(
    Register array, Register index, DoubleRegister value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  add(scratch, array, Operand(index, LSL, kDoubleSizeLog2));
  vstr(value, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::LoadSignedField(Register result,
                                             MemOperand operand, int size) {
  if (size == 1) {
    ldrsb(result, operand);
  } else if (size == 2) {
    ldrsh(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    ldr(result, operand);
  }
}

inline void MaglevAssembler::LoadUnsignedField(Register result,
                                               MemOperand operand, int size) {
  if (size == 1) {
    ldrb(result, operand);
  } else if (size == 2) {
    ldrh(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    ldr(result, operand);
  }
}

inline void MaglevAssembler::SetSlotAddressForTaggedField(Register slot_reg,
                                                          Register object,
                                                          int offset) {
  add(slot_reg, object, Operand(offset - kHeapObjectTag));
}
inline void MaglevAssembler::SetSlotAddressForFixedArrayElement(
    Register slot_reg, Register object, Register index) {
  add(slot_reg, object,
      Operand(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag));
  add(slot_reg, slot_reg, Operand(index, LSL, kTaggedSizeLog2));
}

inline void MaglevAssembler::StoreTaggedFieldNoWriteBarrier(Register object,
                                                            int offset,
                                                            Register value) {
  MacroAssembler::StoreTaggedField(value, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreFixedArrayElementNoWriteBarrier(
    Register array, Register index, Register value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  add(scratch, array, Operand(index, LSL, kTaggedSizeLog2));
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
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  Move(scratch, value);
  MacroAssembler::StoreTaggedField(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreInt32Field(Register object, int offset,
                                             int32_t value) {
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch();
  Move(scratch, value);
  str(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreField(MemOperand operand, Register value,
                                        int size) {
  DCHECK(size == 1 || size == 2 || size == 4);
  if (size == 1) {
    strb(value, operand);
  } else if (size == 2) {
    strh(value, operand);
  } else {
    DCHECK_EQ(size, 4);
    str(value, operand);
  }
}

inline void MaglevAssembler::ReverseByteOrder(Register value, int size) {
  if (size == 2) {
    rev(value, value);
    asr(value, value, Operand(16));
  } else if (size == 4) {
    rev(value, value);
  } else {
    DCHECK_EQ(size, 1);
  }
}

inline void MaglevAssembler::IncrementInt32(Register reg) {
  add(reg, reg, Operand(1));
}

inline void MaglevAssembler::DecrementInt32(Register reg) {
  sub(reg, reg, Operand(1));
}

inline void MaglevAssembler::AddInt32(Register reg, int amount) {
  add(reg, reg, Operand(amount));
}

inline void MaglevAssembler::AndInt32(Register reg, int mask) {
  and_(reg, reg, Operand(mask));
}

inline void MaglevAssembler::OrInt32(Register reg, int mask) {
  orr(reg, reg, Operand(mask));
}

inline void MaglevAssembler::ShiftLeft(Register reg, int amount) {
  lsl(reg, reg, Operand(amount));
}

inline void MaglevAssembler::IncrementAddress(Register reg, int32_t delta) {
  add(reg, reg, Operand(delta));
}

inline void MaglevAssembler::LoadAddress(Register dst, MemOperand location) {
  DCHECK_EQ(location.am(), Offset);
  add(dst, location.rn(), Operand(location.offset()));
}

inline void MaglevAssembler::Call(Label* target) { bl(target); }

inline void MaglevAssembler::EmitEnterExitFrame(int extra_slots,
                                                StackFrame::Type frame_type,
                                                Register c_function,
                                                Register scratch) {
  EnterExitFrame(scratch, extra_slots, frame_type);
}

inline void MaglevAssembler::Move(StackSlot dst, Register src) {
  str(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(StackSlot dst, DoubleRegister src) {
  vstr(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(Register dst, StackSlot src) {
  ldr(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(DoubleRegister dst, StackSlot src) {
  vldr(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(MemOperand dst, Register src) {
  str(src, dst);
}
inline void MaglevAssembler::Move(Register dst, MemOperand src) {
  ldr(dst, src);
}
inline void MaglevAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  if (dst != src) {
    vmov(dst, src);
  }
}
inline void MaglevAssembler::Move(Register dst, Tagged<Smi> src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, ExternalReference src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Register src) {
  if (dst != src) {
    mov(dst, src);
  }
}
inline void MaglevAssembler::Move(Register dst, Tagged<TaggedIndex> i) {
  mov(dst, Operand(i.ptr()));
}
inline void MaglevAssembler::Move(Register dst, int32_t i) {
  mov(dst, Operand(i));
}
inline void MaglevAssembler::Move(Register dst, uint32_t i) {
  mov(dst, Operand(static_cast<int32_t>(i)));
}
inline void MaglevAssembler::Move(DoubleRegister dst, double n) {
  vmov(dst, base::Double(n));
}
inline void MaglevAssembler::Move(DoubleRegister dst, Float64 n) {
  vmov(dst, base::Double(n.get_bits()));
}
inline void MaglevAssembler::Move(Register dst, Handle<HeapObject> obj) {
  MacroAssembler::Move(dst, obj);
}
inline void MaglevAssembler::MoveTagged(Register dst, Handle<HeapObject> obj) {
  Move(dst, obj);
}

inline void MaglevAssembler::LoadFloat32(DoubleRegister dst, MemOperand src) {
  UseScratchRegisterScope temps(this);
  SwVfpRegister temp_vfps = SwVfpRegister::no_reg();
  if (dst.code() < 16) {
    temp_vfps = LowDwVfpRegister::from_code(dst.code()).low();
  } else {
    temp_vfps = temps.AcquireS();
  }
  vldr(temp_vfps, src);
  vcvt_f64_f32(dst, temp_vfps);
}
inline void MaglevAssembler::StoreFloat32(MemOperand dst, DoubleRegister src) {
  UseScratchRegisterScope temps(this);
  SwVfpRegister temp_vfps = temps.AcquireS();
  vcvt_f32_f64(temp_vfps, src);
  vstr(temp_vfps, dst);
}
inline void MaglevAssembler::LoadFloat64(DoubleRegister dst, MemOperand src) {
  vldr(dst, src);
}
inline void MaglevAssembler::StoreFloat64(MemOperand dst, DoubleRegister src) {
  vstr(src, dst);
}

inline void MaglevAssembler::LoadUnalignedFloat64(DoubleRegister dst,
                                                  Register base,
                                                  Register index) {
  // vldr only works on 4 bytes aligned access.
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ldr(scratch, MemOperand(base, index));
  VmovLow(dst, scratch);
  add(scratch, index, Operand(4));
  ldr(scratch, MemOperand(base, scratch));
  VmovHigh(dst, scratch);
}
inline void MaglevAssembler::LoadUnalignedFloat64AndReverseByteOrder(
    DoubleRegister dst, Register base, Register index) {
  // vldr only works on 4 bytes aligned access.
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  ldr(scratch, MemOperand(base, index));
  rev(scratch, scratch);
  VmovHigh(dst, scratch);
  add(scratch, index, Operand(4));
  ldr(scratch, MemOperand(base, scratch));
  rev(scratch, scratch);
  VmovLow(dst, scratch);
}
inline void MaglevAssembler::StoreUnalignedFloat64(Register base,
                                                   Register index,
                                                   DoubleRegister src) {
  // vstr only works on 4 bytes aligned access.
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register index_scratch = temps.AcquireScratch();
  VmovLow(scratch, src);
  str(scratch, MemOperand(base, index));
  add(index_scratch, index, Operand(4));
  VmovHigh(scratch, src);
  str(scratch, MemOperand(base, index_scratch));
}
inline void MaglevAssembler::ReverseByteOrderAndStoreUnalignedFloat64(
    Register base, Register index, DoubleRegister src) {
  // vstr only works on 4 bytes aligned access.
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Register index_scratch = temps.AcquireScratch();
  VmovHigh(scratch, src);
  rev(scratch, scratch);
  str(scratch, MemOperand(base, index));
  add(index_scratch, index, Operand(4));
  VmovLow(scratch, src);
  rev(scratch, scratch);
  str(scratch, MemOperand(base, index_scratch));
}

inline void MaglevAssembler::SignExtend32To64Bits(Register dst, Register src) {
  // No 64-bit registers.
}
inline void MaglevAssembler::NegateInt32(Register val) {
  rsb(val, val, Operand(0));
}

inline void MaglevAssembler::ToUint8Clamped(Register result,
                                            DoubleRegister value, Label* min,
                                            Label* max, Label* done) {
  CpuFeatureScope scope(this, ARMv8);
  TemporaryRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireScratchDouble();
  Move(scratch, 0.0);
  VFPCompareAndSetFlags(scratch, value);
  // Set to 0 if NaN.
  JumpIf(kOverflow, min);
  JumpIf(kGreaterThanEqual, min);
  Move(scratch, 255.0);
  VFPCompareAndSetFlags(value, scratch);
  JumpIf(kGreaterThanEqual, max);
  // if value in [0, 255], then round up to the nearest.
  vrintn(scratch, value);
  TruncateDoubleToInt32(result, scratch);
  Jump(done);
}

template <typename NodeT>
inline void MaglevAssembler::DeoptIfBufferDetached(Register array,
                                                   Register scratch,
                                                   NodeT* node) {
    // A detached buffer leads to megamorphic feedback, so we won't have a deopt
    // loop if we deopt here.
    LoadTaggedField(scratch,
                    FieldMemOperand(array, JSArrayBufferView::kBufferOffset));
    LoadTaggedField(scratch,
                    FieldMemOperand(scratch, JSArrayBuffer::kBitFieldOffset));
    tst(scratch, Operand(JSArrayBuffer::WasDetachedBit::kMask));
    EmitEagerDeoptIf(ne, DeoptimizeReason::kArrayBufferWasDetached, node);
}

inline void MaglevAssembler::LoadByte(Register dst, MemOperand src) {
  ldrb(dst, src);
}

inline Condition MaglevAssembler::IsCallableAndNotUndetectable(
    Register map, Register scratch) {
  ldrb(scratch, FieldMemOperand(map, Map::kBitFieldOffset));
  and_(scratch, scratch,
       Operand(Map::Bits1::IsUndetectableBit::kMask |
               Map::Bits1::IsCallableBit::kMask));
  cmp(scratch, Operand(Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline Condition MaglevAssembler::IsNotCallableNorUndetactable(
    Register map, Register scratch) {
  ldrb(scratch, FieldMemOperand(map, Map::kBitFieldOffset));
  tst(scratch, Operand(Map::Bits1::IsUndetectableBit::kMask |
                       Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline void MaglevAssembler::LoadInstanceType(Register instance_type,
                                              Register heap_object) {
  LoadMap(instance_type, heap_object);
  ldrh(instance_type, FieldMemOperand(instance_type, Map::kInstanceTypeOffset));
}

inline void MaglevAssembler::JumpIfObjectType(Register heap_object,
                                              InstanceType type, Label* target,
                                              Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectType(heap_object, scratch, scratch, type);
  JumpIf(kEqual, target, distance);
}

inline void MaglevAssembler::JumpIfNotObjectType(Register heap_object,
                                                 InstanceType type,
                                                 Label* target,
                                                 Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectType(heap_object, scratch, scratch, type);
  JumpIf(kNotEqual, target, distance);
}

inline void MaglevAssembler::AssertObjectType(Register heap_object,
                                              InstanceType type,
                                              AbortReason reason) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareObjectType(heap_object, scratch, scratch, type);
  Assert(kEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectType(
    Register heap_object, InstanceType type, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectType(heap_object, scratch, scratch, type);
  Branch(kEqual, if_true, true_distance, fallthrough_when_true, if_false,
         false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::JumpIfObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     Label* target,
                                                     Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  JumpIf(kUnsignedLessThanEqual, target, distance);
}

inline void MaglevAssembler::JumpIfObjectTypeNotInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  JumpIf(kUnsignedGreaterThan, target, distance);
}

inline void MaglevAssembler::AssertObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     AbortReason reason) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  Assert(kUnsignedLessThanEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectTypeInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* if_true, Label::Distance true_distance, bool fallthrough_when_true,
    Label* if_false, Label::Distance false_distance,
    bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  CompareObjectTypeRange(heap_object, scratch, scratch, scratch, lower_limit,
                         higher_limit);
  Branch(kUnsignedLessThanEqual, if_true, true_distance, fallthrough_when_true,
         if_false, false_distance, fallthrough_when_false);
}

inline void MaglevAssembler::JumpIfJSAnyIsNotPrimitive(
    Register heap_object, Label* target, Label::Distance distance) {
  // If the type of the result (stored in its map) is less than
  // FIRST_JS_RECEIVER_TYPE, it is not an object in the ECMA sense.
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareObjectType(heap_object, scratch, scratch,
                                    FIRST_JS_RECEIVER_TYPE);
  JumpIf(kUnsignedGreaterThanEqual, target, distance);
}

inline void MaglevAssembler::CompareMapWithRoot(Register object,
                                                RootIndex index,
                                                Register scratch) {
  LoadMap(scratch, object);
  CompareRoot(scratch, index);
}

inline void MaglevAssembler::CompareInstanceType(Register map,
                                                 InstanceType instance_type) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareInstanceType(map, scratch, instance_type);
}

inline Condition MaglevAssembler::CompareInstanceTypeRange(
    Register map, Register instance_type_out, InstanceType lower_limit,
    InstanceType higher_limit) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  MacroAssembler::CompareInstanceTypeRange(map, instance_type_out, scratch,
                                           lower_limit, higher_limit);
  return kUnsignedLessThanEqual;
}

inline void MaglevAssembler::CompareFloat64AndJumpIf(
    DoubleRegister src1, DoubleRegister src2, Condition cond, Label* target,
    Label* nan_failed, Label::Distance distance) {
  VFPCompareAndSetFlags(src1, src2);
  JumpIf(ConditionForNaN(), nan_failed);
  JumpIf(cond, target, distance);
}

inline void MaglevAssembler::CompareFloat64AndBranch(
    DoubleRegister src1, DoubleRegister src2, Condition cond,
    BasicBlock* if_true, BasicBlock* if_false, BasicBlock* next_block,
    BasicBlock* nan_failed) {
  VFPCompareAndSetFlags(src1, src2);
  JumpIf(ConditionForNaN(), nan_failed->label());
  Branch(cond, if_true, if_false, next_block);
}

inline void MaglevAssembler::PrepareCallCFunction(int num_reg_arguments,
                                                  int num_double_registers) {
  MacroAssembler::PrepareCallCFunction(num_reg_arguments, num_double_registers);
}

inline void MaglevAssembler::CallSelf() {
  DCHECK(code_gen_state()->entry_label()->is_bound());
  bl(code_gen_state()->entry_label());
}

inline void MaglevAssembler::Jump(Label* target, Label::Distance) {
  // Any eager deopts should go through JumpIf to enable us to support the
  // `--deopt-every-n-times` stress mode. See EmitEagerDeoptStress.
  DCHECK(!IsDeoptLabel(target));
  b(target);
}

inline void MaglevAssembler::JumpToDeopt(Label* target) {
  DCHECK(IsDeoptLabel(target));
  b(target);
}

inline void MaglevAssembler::EmitEagerDeoptStress(Label* target) {
  // TODO(olivf): On arm `--deopt-every-n-times` is currently not supported.
  // Supporting it would require to implement this method, additionally handle
  // deopt branches in Cbz, and handle all cases where we fall through to the
  // deopt branch (like Int32Divide).
}

inline void MaglevAssembler::JumpIf(Condition cond, Label* target,
                                    Label::Distance) {
  b(target, cond);
}

inline void MaglevAssembler::JumpIfRoot(Register with, RootIndex index,
                                        Label* if_equal,
                                        Label::Distance distance) {
  MacroAssembler::JumpIfRoot(with, index, if_equal);
}

inline void MaglevAssembler::JumpIfNotRoot(Register with, RootIndex index,
                                           Label* if_not_equal,
                                           La
"""


```