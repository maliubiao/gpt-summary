Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Understanding - Context is Key:**

The prompt explicitly states this is a V8 source file located in `v8/src/maglev/arm64/`. This immediately tells us several things:

* **V8:**  This is part of the core JavaScript engine used in Chrome and Node.js.
* **Maglev:** This points to a specific optimization pipeline within V8. Maglev is a mid-tier optimizing compiler, less aggressive than TurboFan but faster than the baseline interpreter.
* **ARM64:** This specifies the target architecture. The code will contain ARM64 assembly instructions.
* **`.h` file:** This is a C++ header file, meaning it contains declarations, inline functions, and template definitions. It's meant to be included in other C++ files.
* **`-inl.h` suffix:** This convention often indicates inline implementations of class methods declared in a corresponding `.h` file. In this case, it's likely the inline implementation of methods declared in `maglev-assembler-arm64.h`.

**2. High-Level Overview of Purpose:**

Given the name "MaglevAssembler," the core function is clearly about generating machine code. Specifically, it's an *assembler* for the Maglev compiler targeting the ARM64 architecture. This means it provides an interface to emit ARM64 instructions.

**3. Scanning for Key Features and Patterns:**

Now, we start reading through the code, looking for recurring patterns and important keywords:

* **Includes:** The `#include` directives tell us about dependencies. We see headers related to code generation (`codegen/`), compilation (`compiler/`), and Maglev itself (`maglev/`). This confirms the code generation purpose. `macro-assembler-inl.h` is a crucial indicator that this class builds upon a lower-level assembler.
* **Namespaces:**  The code is within the `v8::internal::maglev` namespace, reinforcing the context.
* **`constexpr` functions:** Functions like `ConditionForFloat64` and `ShiftFromScale` are computed at compile time. They provide utility calculations related to ARM64 instructions (conditions, shifts).
* **`class MaglevAssembler::TemporaryRegisterScope`:** This class manages the allocation and release of temporary registers. Register management is a fundamental aspect of code generation. The nested `SavedData` struct suggests a mechanism for saving and restoring register states, potentially for deferring code generation.
* **`class MapCompare`:** This class handles comparisons against object maps (metadata describing object structure). Map checks are essential for dynamic language optimizations. The `Generate` method suggests emitting code for the comparison.
* **`namespace detail`:**  This namespace usually contains implementation details not intended for direct external use. We see template functions like `ToRegister`, `PushAllHelper`, and `PushAligned`, which are clearly helper functions for emitting instructions with different argument types and handling stack manipulation. The complexity of the `PushAllHelper` suggests careful consideration of stack alignment and register usage.
* **`MaglevAssembler::Push` and `MaglevAssembler::PushReverse`:** These methods are for pushing values onto the stack. The separate "Reverse" version implies a specific order requirement.
* **Inline functions for basic ARM64 operations:**  There are many inline functions like `SmiTagInt32AndSetFlags`, `CheckInt32IsSmi`, `SmiAddConstant`, `Move`, `LoadFloat64`, `StoreFloat64`, etc. These are wrappers around lower-level `MacroAssembler` instructions, providing a higher-level, Maglev-specific interface. The function names clearly correspond to common assembly operations.
* **Functions for accessing object fields:**  Functions like `LoadTaggedFieldByIndex`, `LoadFixedArrayElement`, `StoreTaggedFieldNoWriteBarrier` deal with accessing object properties and array elements. These are critical for manipulating JavaScript objects in generated code.
* **Deoptimization support:**  The `DeoptIfBufferDetached` function shows how the generated code can trigger deoptimization (falling back to less optimized code) if certain conditions are met.
* **Type checking:** Functions like `IsCallableAndNotUndetectable`, `JumpIfObjectType`, `AssertObjectType` are used to generate code that checks the type of JavaScript objects. This is necessary because JavaScript is dynamically typed.
* **Stack slot management:** Functions like `StackSlotOperand` and `GetStackSlot` are used to access local variables stored on the stack.

**4. Identifying Javascript Connections (Instruction #3):**

Many of the generated instructions directly relate to JavaScript operations:

* **Map comparisons:**  Used to check the type of an object, essential for method dispatch and property access. (Example: `typeof obj === 'object'`)
* **Smi operations:**  Smis (Small Integers) are a common representation for numbers in JavaScript. The functions for tagging, checking, adding, and subtracting Smis directly correspond to JavaScript integer operations. (Example: `x + 1`)
* **Heap number operations:**  JavaScript numbers are often represented as double-precision floating-point values (HeapNumbers). The functions for moving, loading, and storing HeapNumbers handle these values. (Example: `3.14`)
* **Array access:**  The functions for loading and storing elements in FixedArrays and FixedDoubleArrays implement JavaScript array access. (Example: `arr[i]`)
* **Typed array operations:** Functions for handling TypedArrays are crucial for efficient binary data manipulation in JavaScript. (Example: `new Uint8Array(buffer)[i]`)
* **Object property access:**  Loading and storing tagged fields implements JavaScript property access. (Example: `obj.property`)
* **Function calls:** The `Call` instruction relates to JavaScript function calls.
* **Type checking:**  JavaScript's dynamic nature requires runtime type checks. The functions for checking object types are directly tied to this.

**5. Inferring Functionality and Summarizing (Instructions #1 and #6):**

Based on the observations above, we can summarize the file's functionality:

* **Primary Role:**  Provides a high-level C++ interface (`MaglevAssembler`) for generating ARM64 assembly code specifically tailored for the V8 Maglev compiler.
* **Key Features:**
    * **Register Management:**  Efficiently allocates and manages temporary registers.
    * **Instruction Emission:** Offers methods to emit a wide range of ARM64 instructions, often specialized for V8's internal data representations (Smis, HeapNumbers, Tagged Pointers).
    * **Object Model Support:** Provides functions for interacting with V8's object model, including map checks, field access, and array manipulation.
    * **Stack Management:**  Includes functions for pushing and popping values from the stack, with considerations for alignment.
    * **Deoptimization:**  Supports generating code that can trigger deoptimization when necessary.
    * **Type Checking:** Offers primitives for generating code that performs runtime type checks on JavaScript values.

**6. Addressing Torque and Examples (Instructions #2 and #3):**

* **Torque:** The prompt asks about the `.tq` extension. The file ends in `.h`, so it's not a Torque file. Torque is a higher-level language used within V8 to generate C++ code, often for low-level operations.
* **JavaScript Examples:** As detailed in point 4, many of the assembler functions have direct equivalents in JavaScript.

**7. Code Logic and User Errors (Instructions #4 and #5):**

* **Code Logic:** The `ShiftFromScale` function provides a clear example of logic. *Assumption:* Input `n` is a power of 2 (1, 2, 4, 8). *Input:* `n = 4`. *Output:* `2`. This function is likely used to calculate the shift amount for scaled memory access in ARM64 instructions.
* **User Errors:**  Many common programming errors could arise if one were *manually* writing assembly. However, since this is a code *generator*, the errors are more likely to be in the *design* of the code generator itself. Examples of potential issues (though the V8 developers are very careful):
    * **Incorrect register allocation:**  Using the same register for two different purposes at the same time. The `TemporaryRegisterScope` aims to prevent this.
    * **Stack corruption:**  Pushing or popping the wrong number of values, or mismanaging the stack pointer. The `PushAllHelper` attempts to handle alignment.
    * **Type confusion:**  Operating on a value as if it were a different type. The type checking functions are designed to mitigate this at runtime.
    * **Memory access errors:**  Reading or writing to invalid memory locations. V8's object model and garbage collector help prevent this, but incorrect offsets could lead to issues.

This detailed thought process demonstrates how to systematically analyze a complex piece of source code by understanding its context, identifying key components, and relating it to the broader system it belongs to.
这是V8 JavaScript引擎中Maglev优化编译器的ARM64架构特定汇编器头文件（inline部分）。它定义了用于生成ARM64汇编指令的内联函数和辅助类，这些指令构成了Maglev编译器生成的机器代码。

**功能归纳:**

1. **提供ARM64架构特定的汇编指令生成接口:**  `MaglevAssembler` 类及其内联函数提供了在ARM64架构上生成汇编指令的方法。这些方法是对底层 `MacroAssembler` 的封装和扩展，提供了更高级别的抽象，更贴合Maglev编译器的需求。

2. **管理临时寄存器:**  `TemporaryRegisterScope` 类负责在生成汇编代码时临时申请和释放寄存器，避免寄存器冲突，简化寄存器的使用。

3. **支持对象 Map 的比较:** `MapCompare` 类用于比较对象的 Map (类型信息)，这是动态语言优化的重要组成部分。它可以生成比较 Map 的汇编代码，并根据比较结果跳转。

4. **提供便捷的寄存器获取方式:**  `ToRegister` 模板函数可以将不同类型的输入（立即数、寄存器、内存位置）转换为寄存器，方便后续的汇编指令操作。

5. **封装栈操作:**  `Push` 和 `PushReverse` 模板函数用于将多个值压入栈中，并考虑了栈对齐等问题。

6. **提供常见的算术和逻辑运算的汇编指令生成方法:**  例如，`SmiTagInt32AndSetFlags`、`SmiAddConstant`、`Move` 等函数用于生成整数、浮点数以及其他类型的操作指令。

7. **提供内存访问相关的汇编指令生成方法:**  例如，`LoadTaggedFieldByIndex`、`LoadFixedArrayElement`、`StoreTaggedFieldNoWriteBarrier` 等函数用于加载和存储对象的属性、数组元素等。

8. **支持类型检查和断言:**  例如，`CheckInt32IsSmi`、`JumpIfObjectType`、`AssertObjectType` 等函数用于生成类型检查相关的汇编代码，用于确保代码执行的正确性。

9. **支持 Deoptimization（反优化）:** `DeoptIfBufferDetached` 函数用于生成在特定条件下触发反优化的汇编代码。

**关于源代码文件后缀名:**

根据描述，`v8/src/maglev/arm64/maglev-assembler-arm64-inl.h` 的后缀是 `.h`，而不是 `.tq`。因此，它不是一个 V8 Torque 源代码文件，而是一个标准的 C++ 头文件，其中包含了内联函数的定义。 Torque 文件通常用于定义一些底层的操作，并生成对应的 C++ 代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这个头文件中的代码最终是为了高效地执行 JavaScript 代码。它提供的汇编指令生成方法对应着 JavaScript 的各种操作。以下是一些 JavaScript 功能与该文件中汇编指令的对应关系示例：

* **类型检查:** JavaScript 中可以使用 `typeof` 运算符或检查对象的原型链来判断对象的类型。 `JumpIfObjectType` 等函数生成的汇编代码就是为了实现这些类型检查。

   ```javascript
   function checkType(obj) {
     if (typeof obj === 'number') {
       console.log('It's a number!');
     } else if (typeof obj === 'string') {
       console.log('It's a string!');
     }
   }
   ```

* **算术运算:** JavaScript 中的加减乘除等算术运算，会对应到 `SmiAddConstant` 等函数生成的汇编指令。

   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```

* **对象属性访问:** JavaScript 中访问对象的属性（如 `obj.property` 或 `obj['property']`）会对应到 `LoadTaggedFieldByIndex` 等函数生成的汇编指令。

   ```javascript
   const obj = { x: 10, y: 20 };
   console.log(obj.x);
   ```

* **数组元素访问:** JavaScript 中访问数组元素（如 `arr[i]`）会对应到 `LoadFixedArrayElement` 等函数生成的汇编指令。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[1]);
   ```

**代码逻辑推理和假设输入/输出:**

我们以 `ShiftFromScale(int n)` 函数为例进行代码逻辑推理：

**假设输入:** `n = 4`

**代码逻辑:**

```c++
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
```

当输入 `n` 为 4 时，`switch` 语句会匹配到 `case 4:`，然后函数返回 `2`。

**输出:** `2`

**功能解释:** 这个函数将一个缩放因子（通常用于内存访问的偏移量计算）转换为对应的移位量。在 ARM64 指令中，可以使用移位操作来高效地计算偏移量。例如，如果元素大小是 4 字节，那么访问索引 `i` 的元素，相当于偏移量是 `i * 4`，而 `4` 对应的移位量是 `2`（因为 2 的 2 次方是 4）。

**用户常见的编程错误 (如果涉及):**

虽然这个文件是 V8 引擎的内部实现，普通用户不会直接编写或修改它，但理解其背后的概念有助于理解 JavaScript 引擎的工作原理，并避免一些可能导致性能问题的 JavaScript 编程模式。

例如，如果 JavaScript 代码中存在大量的类型转换或频繁的属性访问，Maglev 编译器就需要生成大量的类型检查和内存访问指令，如果这些操作可以优化，就能提高性能。

一个与类型相关的常见错误是过度依赖动态类型，导致引擎难以进行静态分析和优化：

```javascript
function process(input) {
  // 假设 input 可能是数字或字符串
  const result = input * 2; // 如果 input 是字符串，会得到 NaN
  return result;
}

console.log(process(5));    // 输出 10
console.log(process("abc")); // 输出 NaN
```

在这种情况下，编译器可能需要生成额外的代码来处理 `input` 可能为不同类型的情况，影响性能。如果能确保 `input` 的类型一致，编译器就能生成更优化的代码。

**总结 (第 1 部分功能):**

`v8/src/maglev/arm64/maglev-assembler-arm64-inl.h` 文件是 V8 Maglev 编译器在 ARM64 架构上的汇编器内联函数定义，它提供了生成 ARM64 汇编指令的接口，用于实现 JavaScript 各种操作的高效执行。它包含了寄存器管理、Map 比较、栈操作、算术运算、内存访问、类型检查和反优化等功能的支持。这个文件是 Maglev 编译器生成高性能机器码的关键组成部分。

Prompt: 
```
这是目录为v8/src/maglev/arm64/maglev-assembler-arm64-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/arm64/maglev-assembler-arm64-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_MAGLEV_ARM64_MAGLEV_ASSEMBLER_ARM64_INL_H_
#define V8_MAGLEV_ARM64_MAGLEV_ASSEMBLER_ARM64_INL_H_

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
    CPURegList available_scratch_;
    CPURegList available_fp_scratch_;
  };

  explicit TemporaryRegisterScope(MaglevAssembler* masm)
      : Base(masm), scratch_scope_(masm) {}
  explicit TemporaryRegisterScope(MaglevAssembler* masm,
                                  const SavedData& saved_data)
      : Base(masm, saved_data), scratch_scope_(masm) {
    scratch_scope_.SetAvailable(saved_data.available_scratch_);
    scratch_scope_.SetAvailableFP(saved_data.available_fp_scratch_);
  }

  Register AcquireScratch() {
    Register reg = scratch_scope_.AcquireX();
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
        *scratch_scope_.Available(),
        *scratch_scope_.AvailableFP(),
    };
  }

  void ResetToDefaultImpl() {
    scratch_scope_.SetAvailable(masm_->DefaultTmpList());
    scratch_scope_.SetAvailableFP(masm_->DefaultFPTmpList());
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
  masm_->CmpTagged(map_, temp);
  masm_->JumpIf(cond, if_true, distance);
}

Register MapCompare::GetMap() {
  if (PointerCompressionIsEnabled()) {
    // Decompression is idempotent (UXTW operand is used), so this would return
    // a valid pointer even if called multiple times in a row.
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

template <typename... Args>
inline void PushAll(MaglevAssembler* masm, Args... args) {
  PushAllHelper<Args...>::Push(masm, args...);
}

template <typename... Args>
inline void PushAllReverse(MaglevAssembler* masm, Args... args) {
  PushAllHelper<Args...>::PushReverse(masm, args...);
}

template <>
struct PushAllHelper<> {
  static void Push(MaglevAssembler* masm) {}
  static void PushReverse(MaglevAssembler* masm) {}
};

template <typename T, typename... Args>
inline void PushIterator(MaglevAssembler* masm, base::iterator_range<T> range,
                         Args... args) {
  using value_type = typename base::iterator_range<T>::value_type;
  for (auto iter = range.begin(), end = range.end(); iter != end; ++iter) {
    value_type val1 = *iter;
    ++iter;
    if (iter == end) {
      PushAll(masm, val1, args...);
      return;
    }
    value_type val2 = *iter;
    masm->Push(val1, val2);
  }
  PushAll(masm, args...);
}

template <typename T, typename... Args>
inline void PushIteratorReverse(MaglevAssembler* masm,
                                base::iterator_range<T> range, Args... args) {
  using value_type = typename base::iterator_range<T>::value_type;
  using difference_type = typename base::iterator_range<T>::difference_type;
  difference_type count = std::distance(range.begin(), range.end());
  DCHECK_GE(count, 0);
  auto iter = range.rbegin();
  auto end = range.rend();
  if (count % 2 != 0) {
    PushAllReverse(masm, *iter, args...);
    ++iter;
  } else {
    PushAllReverse(masm, args...);
  }
  while (iter != end) {
    value_type val1 = *iter;
    ++iter;
    value_type val2 = *iter;
    ++iter;
    masm->Push(val1, val2);
  }
}

template <typename Arg1, typename Arg2>
inline void PushAligned(MaglevAssembler* masm, Arg1 arg1, Arg2 arg2) {
  if (AlreadyInARegister(arg1) || AlreadyInARegister(arg2)) {
    // If one of the operands is already in a register, there is no need
    // to reuse scratch registers, so two arguments can be pushed together.
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    masm->MacroAssembler::Push(ToRegister(masm, &temps, arg1),
                               ToRegister(masm, &temps, arg2));
    return;
  }
  {
    // Push the first argument together with padding to ensure alignment.
    // The second argument is not pushed together with the first so we can
    // re-use any scratch registers used to materialise the first argument for
    // the second one.
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    masm->MacroAssembler::Push(ToRegister(masm, &temps, arg1), padreg);
  }
  {
    MaglevAssembler::TemporaryRegisterScope temps(masm);
    masm->MacroAssembler::str(ToRegister(masm, &temps, arg2), MemOperand(sp));
  }
}

template <typename Arg>
struct PushAllHelper<Arg> {
  static void Push(MaglevAssembler* masm, Arg arg) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIterator(masm, arg);
    } else {
      FATAL("Unaligned push");
    }
  }
  static void PushReverse(MaglevAssembler* masm, Arg arg) {
    if constexpr (is_iterator_range<Arg>::value) {
      PushIteratorReverse(masm, arg);
    } else {
      PushAllReverse(masm, arg, padreg);
    }
  }
};

template <typename Arg1, typename Arg2, typename... Args>
struct PushAllHelper<Arg1, Arg2, Args...> {
  static void Push(MaglevAssembler* masm, Arg1 arg1, Arg2 arg2, Args... args) {
    if constexpr (is_iterator_range<Arg1>::value) {
      PushIterator(masm, arg1, arg2, args...);
    } else if constexpr (is_iterator_range<Arg2>::value) {
      if (arg2.begin() != arg2.end()) {
        auto val = *arg2.begin();
        PushAligned(masm, arg1, val);
        PushAll(masm,
                base::make_iterator_range(std::next(arg2.begin()), arg2.end()),
                args...);
      } else {
        PushAll(masm, arg1, args...);
      }
    } else {
      PushAligned(masm, arg1, arg2);
      PushAll(masm, args...);
    }
  }
  static void PushReverse(MaglevAssembler* masm, Arg1 arg1, Arg2 arg2,
                          Args... args) {
    if constexpr (is_iterator_range<Arg1>::value) {
      PushIteratorReverse(masm, arg1, arg2, args...);
    } else if constexpr (is_iterator_range<Arg2>::value) {
      if (arg2.begin() != arg2.end()) {
        auto val = *arg2.begin();
        PushAllReverse(
            masm,
            base::make_iterator_range(std::next(arg2.begin()), arg2.end()),
            args...);
        PushAligned(masm, val, arg1);
      } else {
        PushAllReverse(masm, arg1, args...);
      }
    } else {
      PushAllReverse(masm, args...);
      PushAligned(masm, arg2, arg1);
    }
  }
};

}  // namespace detail

template <typename... T>
void MaglevAssembler::Push(T... vals) {
  const int push_count = detail::CountPushHelper<T...>::Count(vals...);
  if (push_count % 2 == 0) {
    detail::PushAll(this, vals...);
  } else {
    detail::PushAll(this, padreg, vals...);
  }
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
    Bind(block->label());
  }
}

inline void MaglevAssembler::SmiTagInt32AndSetFlags(Register dst,
                                                    Register src) {
  if (SmiValuesAre31Bits()) {
    Adds(dst.W(), src.W(), src.W());
  } else {
    SmiTag(dst, src);
  }
}

inline void MaglevAssembler::CheckInt32IsSmi(Register obj, Label* fail,
                                             Register scratch) {
  DCHECK(!SmiValuesAre32Bits());

  Adds(wzr, obj.W(), obj.W());
  JumpIf(kOverflow, fail);
}

inline void MaglevAssembler::SmiAddConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  if (value != 0) {
    if (SmiValuesAre31Bits()) {
      Adds(dst.W(), src.W(), Immediate(Smi::FromInt(value)));
    } else {
      DCHECK(dst.IsX());
      Adds(dst.X(), src.X(), Immediate(Smi::FromInt(value)));
    }
    JumpIf(kOverflow, fail, distance);
  } else {
    Move(dst, src);
  }
}

inline void MaglevAssembler::SmiSubConstant(Register dst, Register src,
                                            int value, Label* fail,
                                            Label::Distance distance) {
  AssertSmi(src);
  if (value != 0) {
    if (SmiValuesAre31Bits()) {
      Subs(dst.W(), src.W(), Immediate(Smi::FromInt(value)));
    } else {
      DCHECK(dst.IsX());
      Subs(dst.X(), src.X(), Immediate(Smi::FromInt(value)));
    }
    JumpIf(kOverflow, fail, distance);
  } else {
    Move(dst, src);
  }
}

inline void MaglevAssembler::MoveHeapNumber(Register dst, double value) {
  Mov(dst, Operand::EmbeddedHeapNumber(value));
}

inline Condition MaglevAssembler::IsRootConstant(Input input,
                                                 RootIndex root_index) {
  if (input.operand().IsRegister()) {
    CompareRoot(ToRegister(input), root_index);
  } else {
    DCHECK(input.operand().IsStackSlot());
    TemporaryRegisterScope temps(this);
    Register scratch = temps.AcquireScratch();
    Ldr(scratch, ToMemOperand(input));
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
  LoadExternalPointerField(
      data_pointer,
      FieldMemOperand(object, JSTypedArray::kExternalPointerOffset));
  if (JSTypedArray::kMaxSizeInHeap == 0) return;
  TemporaryRegisterScope scope(this);
  Register base = scope.AcquireScratch();
  if (COMPRESS_POINTERS_BOOL) {
    Ldr(base.W(), FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  } else {
    Ldr(base, FieldMemOperand(object, JSTypedArray::kBasePointerOffset));
  }
  Add(data_pointer, data_pointer, base);
}

inline MemOperand MaglevAssembler::TypedArrayElementOperand(
    Register data_pointer, Register index, int element_size) {
  Add(data_pointer, data_pointer,
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
  Add(result, object, Operand(index, LSL, ShiftFromScale(scale)));
  MacroAssembler::LoadTaggedField(result, FieldMemOperand(result, offset));
}

inline void MaglevAssembler::LoadBoundedSizeFromObject(Register result,
                                                       Register object,
                                                       int offset) {
  Move(result, FieldMemOperand(object, offset));
#ifdef V8_ENABLE_SANDBOX
  Lsr(result, result, kBoundedSizeShift);
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
  Add(result, array, Operand(index, LSL, kTaggedSizeLog2));
  MacroAssembler::LoadTaggedFieldWithoutDecompressing(
      result, FieldMemOperand(result, OFFSET_OF_DATA_START(FixedArray)));
}

void MaglevAssembler::LoadFixedDoubleArrayElement(DoubleRegister result,
                                                  Register array,
                                                  Register index) {
  MaglevAssembler::TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  if (v8_flags.debug_code) {
    AssertObjectType(array, FIXED_DOUBLE_ARRAY_TYPE,
                     AbortReason::kUnexpectedValue);
    CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                          AbortReason::kUnexpectedNegativeValue);
  }
  Add(scratch, array, Operand(index, LSL, kDoubleSizeLog2));
  Ldr(result, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::StoreFixedDoubleArrayElement(
    Register array, Register index, DoubleRegister value) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Add(scratch, array, Operand(index, LSL, kDoubleSizeLog2));
  Str(value, FieldMemOperand(scratch, OFFSET_OF_DATA_START(FixedArray)));
}

inline void MaglevAssembler::LoadSignedField(Register result,
                                             MemOperand operand, int size) {
  if (size == 1) {
    Ldrsb(result, operand);
  } else if (size == 2) {
    Ldrsh(result, operand);
  } else {
    DCHECK_EQ(size, 4);
    Ldr(result.W(), operand);
  }
}

inline void MaglevAssembler::LoadUnsignedField(Register result,
                                               MemOperand operand, int size) {
  if (size == 1) {
    Ldrb(result.W(), operand);
  } else if (size == 2) {
    Ldrh(result.W(), operand);
  } else {
    DCHECK_EQ(size, 4);
    Ldr(result.W(), operand);
  }
}

inline void MaglevAssembler::SetSlotAddressForTaggedField(Register slot_reg,
                                                          Register object,
                                                          int offset) {
  Add(slot_reg, object, offset - kHeapObjectTag);
}
inline void MaglevAssembler::SetSlotAddressForFixedArrayElement(
    Register slot_reg, Register object, Register index) {
  Add(slot_reg, object, OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  Add(slot_reg, slot_reg, Operand(index, LSL, kTaggedSizeLog2));
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
  Add(scratch, array, Operand(index, LSL, kTaggedSizeLog2));
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
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Mov(scratch, value);
  MacroAssembler::StoreTaggedField(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreInt32Field(Register object, int offset,
                                             int32_t value) {
  if (value == 0) {
    Str(wzr, FieldMemOperand(object, offset));
    return;
  }
  TemporaryRegisterScope scope(this);
  Register scratch = scope.AcquireScratch().W();
  Move(scratch, value);
  Str(scratch, FieldMemOperand(object, offset));
}

inline void MaglevAssembler::StoreField(MemOperand operand, Register value,
                                        int size) {
  DCHECK(size == 1 || size == 2 || size == 4);
  if (size == 1) {
    Strb(value.W(), operand);
  } else if (size == 2) {
    Strh(value.W(), operand);
  } else {
    DCHECK_EQ(size, 4);
    Str(value.W(), operand);
  }
}

#ifdef V8_ENABLE_SANDBOX

inline void MaglevAssembler::StoreTrustedPointerFieldNoWriteBarrier(
    Register object, int offset, Register value) {
  MacroAssembler::StoreTrustedPointerField(value,
                                           FieldMemOperand(object, offset));
}

#endif  // V8_ENABLE_SANDBOX

inline void MaglevAssembler::ReverseByteOrder(Register value, int size) {
  if (size == 2) {
    Rev16(value, value);
    Sxth(value, value);
  } else if (size == 4) {
    Rev32(value, value);
  } else {
    DCHECK_EQ(size, 1);
  }
}

inline void MaglevAssembler::IncrementInt32(Register reg) {
  Add(reg.W(), reg.W(), Immediate(1));
}

inline void MaglevAssembler::DecrementInt32(Register reg) {
  Sub(reg.W(), reg.W(), Immediate(1));
}

inline void MaglevAssembler::AddInt32(Register reg, int amount) {
  Add(reg.W(), reg.W(), Immediate(amount));
}

inline void MaglevAssembler::AndInt32(Register reg, int mask) {
  And(reg.W(), reg.W(), Immediate(mask));
}

inline void MaglevAssembler::OrInt32(Register reg, int mask) {
  Orr(reg.W(), reg.W(), Immediate(mask));
}

inline void MaglevAssembler::ShiftLeft(Register reg, int amount) {
  Lsl(reg.W(), reg.W(), amount);
}

inline void MaglevAssembler::IncrementAddress(Register reg, int32_t delta) {
  Add(reg.X(), reg.X(), Immediate(delta));
}

inline void MaglevAssembler::LoadAddress(Register dst, MemOperand location) {
  DCHECK(location.IsImmediateOffset());
  Add(dst.X(), location.base(), Immediate(location.offset()));
}

inline void MaglevAssembler::Call(Label* target) { bl(target); }

inline void MaglevAssembler::EmitEnterExitFrame(int extra_slots,
                                                StackFrame::Type frame_type,
                                                Register c_function,
                                                Register scratch) {
  EnterExitFrame(scratch, extra_slots, frame_type);
}

inline void MaglevAssembler::Move(StackSlot dst, Register src) {
  Str(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(StackSlot dst, DoubleRegister src) {
  Str(src, StackSlotOperand(dst));
}
inline void MaglevAssembler::Move(Register dst, StackSlot src) {
  Ldr(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(DoubleRegister dst, StackSlot src) {
  Ldr(dst, StackSlotOperand(src));
}
inline void MaglevAssembler::Move(MemOperand dst, Register src) {
  Str(src, dst);
}
inline void MaglevAssembler::Move(Register dst, MemOperand src) {
  Ldr(dst, src);
}
inline void MaglevAssembler::Move(DoubleRegister dst, DoubleRegister src) {
  Fmov(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Tagged<Smi> src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, ExternalReference src) {
  Mov(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Register src) {
  MacroAssembler::Move(dst, src);
}
inline void MaglevAssembler::Move(Register dst, Tagged<TaggedIndex> i) {
  Mov(dst, i.ptr());
}
inline void MaglevAssembler::Move(Register dst, int32_t i) {
  Mov(dst.W(), Immediate(i));
}
inline void MaglevAssembler::Move(Register dst, uint32_t i) {
  Mov(dst.W(), Immediate(i));
}
inline void MaglevAssembler::Move(Register dst, IndirectPointerTag i) {
  Mov(dst, Immediate(i));
}
inline void MaglevAssembler::Move(DoubleRegister dst, double n) {
  Fmov(dst, n);
}
inline void MaglevAssembler::Move(DoubleRegister dst, Float64 n) {
  Fmov(dst, n.get_scalar());
}
inline void MaglevAssembler::Move(Register dst, Handle<HeapObject> obj) {
  Mov(dst, Operand(obj));
}
void MaglevAssembler::MoveTagged(Register dst, Handle<HeapObject> obj) {
#ifdef V8_COMPRESS_POINTERS
  Mov(dst.W(), Operand(obj, RelocInfo::COMPRESSED_EMBEDDED_OBJECT));
#else
  Mov(dst, Operand(obj));
#endif
}

inline void MaglevAssembler::LoadFloat32(DoubleRegister dst, MemOperand src) {
  Ldr(dst.S(), src);
  Fcvt(dst, dst.S());
}
inline void MaglevAssembler::StoreFloat32(MemOperand dst, DoubleRegister src) {
  TemporaryRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireScratchDouble();
  Fcvt(scratch.S(), src);
  Str(scratch.S(), dst);
}
inline void MaglevAssembler::LoadFloat64(DoubleRegister dst, MemOperand src) {
  Ldr(dst, src);
}
inline void MaglevAssembler::StoreFloat64(MemOperand dst, DoubleRegister src) {
  Str(src, dst);
}

inline void MaglevAssembler::LoadUnalignedFloat64(DoubleRegister dst,
                                                  Register base,
                                                  Register index) {
  LoadFloat64(dst, MemOperand(base, index));
}
inline void MaglevAssembler::LoadUnalignedFloat64AndReverseByteOrder(
    DoubleRegister dst, Register base, Register index) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Ldr(scratch, MemOperand(base, index));
  Rev(scratch, scratch);
  Fmov(dst, scratch);
}
inline void MaglevAssembler::StoreUnalignedFloat64(Register base,
                                                   Register index,
                                                   DoubleRegister src) {
  StoreFloat64(MemOperand(base, index), src);
}
inline void MaglevAssembler::ReverseByteOrderAndStoreUnalignedFloat64(
    Register base, Register index, DoubleRegister src) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  Fmov(scratch, src);
  Rev(scratch, scratch);
  Str(scratch, MemOperand(base, index));
}

inline void MaglevAssembler::SignExtend32To64Bits(Register dst, Register src) {
  Mov(dst, Operand(src.W(), SXTW));
}
inline void MaglevAssembler::NegateInt32(Register val) {
  Neg(val.W(), val.W());
}

inline void MaglevAssembler::ToUint8Clamped(Register result,
                                            DoubleRegister value, Label* min,
                                            Label* max, Label* done) {
  TemporaryRegisterScope temps(this);
  DoubleRegister scratch = temps.AcquireScratchDouble();
  Move(scratch, 0.0);
  Fcmp(scratch, value);
  // Set to 0 if NaN.
  B(vs, min);
  B(ge, min);
  Move(scratch, 255.0);
  Fcmp(value, scratch);
  B(ge, max);
  // if value in [0, 255], then round up to the nearest.
  Frintn(scratch, value);
  TruncateDoubleToInt32(result, scratch);
  B(done);
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
    Tst(scratch.W(), Immediate(JSArrayBuffer::WasDetachedBit::kMask));
    EmitEagerDeoptIf(ne, DeoptimizeReason::kArrayBufferWasDetached, node);
}

inline void MaglevAssembler::LoadByte(Register dst, MemOperand src) {
  Ldrb(dst, src);
}

inline Condition MaglevAssembler::IsCallableAndNotUndetectable(
    Register map, Register scratch) {
  Ldrb(scratch.W(), FieldMemOperand(map, Map::kBitFieldOffset));
  And(scratch.W(), scratch.W(),
      Map::Bits1::IsUndetectableBit::kMask | Map::Bits1::IsCallableBit::kMask);
  Cmp(scratch.W(), Map::Bits1::IsCallableBit::kMask);
  return kEqual;
}

inline Condition MaglevAssembler::IsNotCallableNorUndetactable(
    Register map, Register scratch) {
  Ldrb(scratch.W(), FieldMemOperand(map, Map::kBitFieldOffset));
  Tst(scratch.W(), Immediate(Map::Bits1::IsUndetectableBit::kMask |
                             Map::Bits1::IsCallableBit::kMask));
  return kEqual;
}

inline void MaglevAssembler::LoadInstanceType(Register instance_type,
                                              Register heap_object) {
  LoadMap(instance_type, heap_object);
  Ldrh(instance_type.W(),
       FieldMemOperand(instance_type, Map::kInstanceTypeOffset));
}

inline void MaglevAssembler::JumpIfObjectType(Register heap_object,
                                              InstanceType type, Label* target,
                                              Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectType(heap_object, scratch, scratch, type);
  JumpIf(kEqual, target, distance);
}

inline void MaglevAssembler::JumpIfNotObjectType(Register heap_object,
                                                 InstanceType type,
                                                 Label* target,
                                                 Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectType(heap_object, scratch, scratch, type);
  JumpIf(kNotEqual, target, distance);
}

inline void MaglevAssembler::AssertObjectType(Register heap_object,
                                              InstanceType type,
                                              AbortReason reason) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  AssertNotSmi(heap_object);
  IsObjectType(heap_object, scratch, scratch, type);
  Assert(kEqual, reason);
}

inline void MaglevAssembler::BranchOnObjectType(
    Register heap_object, InstanceType type, Label* if_true,
    Label::Distance true_distance, bool fallthrough_when_true, Label* if_false,
    Label::Distance false_distance, bool fallthrough_when_false) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectType(heap_object, scratch, scratch, type);
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
  IsObjectTypeInRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedLessThanEqual, target, distance);
}

inline void MaglevAssembler::JumpIfObjectTypeNotInRange(
    Register heap_object, InstanceType lower_limit, InstanceType higher_limit,
    Label* target, Label::Distance distance) {
  TemporaryRegisterScope temps(this);
  Register scratch = temps.AcquireScratch();
  IsObjectTypeInRange(heap_object, scratch, lower_limit, higher_limit);
  JumpIf(kUnsignedGreaterThan, target, distance);
}

inline void MaglevAssembler::AssertObjectTypeInRange(Register heap_object,
                                                     InstanceType lower_limit,
                                                     InstanceType higher_limit,
                                                     AbortReason reason) {
  TemporaryRegisterScope temps(this);
  Register s
"""


```