Response: The user wants a summary of the functionality of the C++ code provided, which is the first part of a larger file. I need to analyze the code and identify its main purpose.

The code seems to be part of the V8 JavaScript engine, specifically the instruction selection phase for the PowerPC (PPC) architecture. It defines how high-level operations are translated into low-level PPC instructions.

Key aspects to consider:
- **Instruction Selection:** The core purpose is selecting the appropriate PPC instructions.
- **Operand Generation:**  It handles the creation of operands for the selected instructions, including immediate values and registers.
- **Architecture-Specific Logic:** The code contains PPC-specific logic, like handling different addressing modes and immediate value constraints.
- **Interaction with Turbofan/Turboshaft:** The code uses templates to work with both Turbofan and Turboshaft, V8's optimizing compilers.
- **Support for Various Operations:** It includes code for handling various operations like loads, stores, arithmetic, and logical operations.
- **JavaScript Relevance:** The code directly contributes to the performance of JavaScript code execution on PPC architectures by optimizing the generated machine code.

I will structure the summary to cover these points and provide a JavaScript example if applicable.
这个C++代码文件是V8 JavaScript引擎针对PowerPC (PPC) 架构的**指令选择器 (Instruction Selector)** 的一部分。它的主要功能是将高级的、与架构无关的中间表示 (Intermediate Representation, IR) 的操作 (例如来自 Turbofan 或 Turboshaft 编译器的节点) 转换为底层的、PPC架构特定的机器指令。

更具体地说，这个代码片段实现了以下功能：

1. **定义了PPC特定的操作数生成器 (PPCOperandGeneratorT):** 这个模板类继承自通用的操作数生成器，并添加了PPC架构特有的方法，用于生成指令的操作数。例如，它可以判断一个节点是否可以表示为立即数，并根据不同的立即数模式 (ImmediateMode) 生成相应的操作数。
2. **定义了立即数模式枚举 (ImmediateMode):**  列举了PPC架构支持的各种立即数类型，如16位有符号立即数、16位无符号立即数、移位立即数等。这用于在指令选择时判断是否可以使用立即数，从而生成更紧凑高效的指令。
3. **实现了多种指令的 "访问" (Visit) 方法:**  针对不同的IR节点类型 (例如 `StackSlot`, `Load`, `Store`, `Word32And`, `Word32Or` 等)，定义了相应的 `Visit` 方法。这些方法负责：
    - 判断适合当前操作的最佳PPC指令。
    - 使用 `PPCOperandGeneratorT` 生成指令的操作数。
    - 调用 `selector->Emit` 发射 (emit) 生成的PPC指令。
4. **处理内存访问操作 (Load 和 Store):**  `VisitLoad` 和 `VisitStore` 方法根据加载/存储的数据类型、是否需要写屏障等信息，选择合适的PPC加载和存储指令。它还考虑了不同的寻址模式 (例如使用立即数偏移或寄存器偏移)。
5. **处理算术和逻辑运算:**  例如 `VisitWord32And`, `VisitWord32Or`, `VisitWord32Xor`, `VisitWord32Shl` 等方法，将IR的位运算、移位操作等转换为对应的PPC指令，并尝试进行一些优化，例如将逻辑与操作与移位操作合并为一条指令 (例如 `rlwinm`)。
6. **处理栈操作:** `VisitStackSlot` 用于分配栈空间。
7. **处理条件分支:** `VisitStackPointerGreaterThan` 用于生成栈指针比较指令，通常用于栈溢出检查。
8. **支持 Turbofan 和 Turboshaft 编译器:**  使用了模板 `template <typename Adapter>`，使得这段代码可以同时被 V8 的两个优化编译器框架 (Turbofan 和 Turboshaft) 使用。

**与JavaScript的功能关系:**

这个代码文件直接影响了V8 JavaScript引擎在PPC架构上的性能。当JavaScript代码被 Turbofan 或 Turboshaft 编译优化时，指令选择器会将编译后的中间表示转换为实际的机器码。选择合适的指令和利用PPC架构的特性 (例如立即数寻址、合并指令等) 可以显著提高JavaScript代码的执行效率。

**JavaScript 示例说明:**

虽然这个C++文件本身不包含JavaScript代码，但它的功能是为执行JavaScript代码服务的。以下是一些JavaScript代码示例，它们执行时可能会触发此文件中实现的指令选择逻辑：

```javascript
function add(a, b) {
  return a + b;
}

let x = 10;
let y = x << 2; // 左移操作
let z = x & 0xF;  // 位与操作

let arr = [1, 2, 3];
let first = arr[0]; // 数组元素访问 (Load)
arr[1] = 4;         // 数组元素赋值 (Store)

if (x > 5) {
  console.log("x is greater than 5");
}
```

当V8引擎执行上述JavaScript代码时，Turbofan或 Turboshaft 可能会将这些高级操作编译成如下的中间表示形式（这只是一个概念性的例子）：

- `a + b`:  会被编译成一个加法操作节点。
- `x << 2`: 会被编译成一个左移操作节点。
- `x & 0xF`: 会被编译成一个按位与操作节点。
- `arr[0]`: 会被编译成一个加载数组元素的操作节点。
- `arr[1] = 4`: 会被编译成一个存储数组元素的操作节点。
- `x > 5`:  会被编译成一个比较操作节点。

`instruction-selector-ppc.cc` 文件中的代码就是负责将这些中间表示的节点转换为具体的PPC机器指令。例如，对于 `x << 2`，`VisitWord32Shl` 方法可能会选择一个PPC的移位指令，并将 `x` 对应的寄存器和立即数 `2` 作为操作数。对于 `arr[0]`，`VisitLoad` 方法会生成一个PPC的加载指令，计算数组元素的地址并将其加载到寄存器中。

总结来说，`instruction-selector-ppc.cc` 是 V8 引擎中一个关键的组成部分，它确保了 JavaScript 代码可以在 PowerPC 架构上高效地执行。

Prompt: 
```
这是目录为v8/src/compiler/backend/ppc/instruction-selector-ppc.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/base/iterator.h"
#include "src/compiler/backend/instruction-selector-impl.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/execution/ppc/frame-constants-ppc.h"
#include "src/roots/roots-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

enum ImmediateMode {
  kInt16Imm,
  kInt16Imm_Unsigned,
  kInt16Imm_Negate,
  kInt16Imm_4ByteAligned,
  kShift32Imm,
  kInt34Imm,
  kShift64Imm,
  kNoImmediate
};

// Adds PPC-specific methods for generating operands.
template <typename Adapter>
class PPCOperandGeneratorT final : public OperandGeneratorT<Adapter> {
 public:
  OPERAND_GENERATOR_T_BOILERPLATE(Adapter)

  explicit PPCOperandGeneratorT<Adapter>(
      InstructionSelectorT<Adapter>* selector)
      : super(selector) {}

  InstructionOperand UseOperand(node_t node, ImmediateMode mode) {
    if (CanBeImmediate(node, mode)) {
      return UseImmediate(node);
    }
    return UseRegister(node);
  }

  bool CanBeImmediate(node_t node, ImmediateMode mode) {
    if (!this->is_constant(node)) return false;
    auto constant = this->constant_view(node);
    if (constant.is_compressed_heap_object()) {
      if (!COMPRESS_POINTERS_BOOL) return false;
      // For builtin code we need static roots
      if (selector()->isolate()->bootstrapper() && !V8_STATIC_ROOTS_BOOL) {
        return false;
      }
      const RootsTable& roots_table = selector()->isolate()->roots_table();
      RootIndex root_index;
      Handle<HeapObject> value = constant.heap_object_value();
      if (roots_table.IsRootHandle(value, &root_index)) {
        if (!RootsTable::IsReadOnly(root_index)) return false;
        return CanBeImmediate(MacroAssemblerBase::ReadOnlyRootPtr(
                                  root_index, selector()->isolate()),
                              mode);
      }
      return false;
    }

    if (!selector()->is_integer_constant(node)) return false;
    int64_t value = selector()->integer_constant(node);
    return CanBeImmediate(value, mode);
  }

  bool CanBeImmediate(int64_t value, ImmediateMode mode) {
    switch (mode) {
      case kInt16Imm:
        return is_int16(value);
      case kInt16Imm_Unsigned:
        return is_uint16(value);
      case kInt16Imm_Negate:
        return is_int16(-value);
      case kInt16Imm_4ByteAligned:
        return is_int16(value) && !(value & 3);
      case kShift32Imm:
        return 0 <= value && value < 32;
      case kInt34Imm:
        return is_int34(value);
      case kShift64Imm:
        return 0 <= value && value < 64;
      case kNoImmediate:
        return false;
    }
    return false;
  }
};

namespace {

template <typename Adapter>
void VisitRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
             typename Adapter::node_t node) {
  PPCOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)));
}

template <typename Adapter>
void VisitRRR(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node) {
  PPCOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseRegister(selector->input_at(node, 1)));
}

template <typename Adapter>
void VisitRRO(InstructionSelectorT<Adapter>* selector, InstructionCode opcode,
              typename Adapter::node_t node, ImmediateMode operand_mode) {
  PPCOperandGeneratorT<Adapter> g(selector);
  selector->Emit(opcode, g.DefineAsRegister(node),
                 g.UseRegister(selector->input_at(node, 0)),
                 g.UseOperand(selector->input_at(node, 1), operand_mode));
}

template <typename Adapter>
void VisitTryTruncateDouble(InstructionSelectorT<Adapter>* selector,
                            InstructionCode opcode,
                            typename Adapter::node_t node) {
  using node_t = typename Adapter::node_t;
  PPCOperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[] = {g.UseRegister(selector->input_at(node, 0))};
  InstructionOperand outputs[2];
  size_t output_count = 0;
  outputs[output_count++] = g.DefineAsRegister(node);

  node_t success_output = selector->FindProjection(node, 1);
  if (selector->valid(success_output)) {
    outputs[output_count++] = g.DefineAsRegister(success_output);
  }

  selector->Emit(opcode, output_count, outputs, 1, inputs);
}

// Shared routine for multiple binary operations.
template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                ImmediateMode operand_mode, FlagsContinuationT<Adapter>* cont) {
  PPCOperandGeneratorT<Adapter> g(selector);
  InstructionOperand inputs[4];
  size_t input_count = 0;
  InstructionOperand outputs[2];
  size_t output_count = 0;

  inputs[input_count++] = g.UseRegister(selector->input_at(node, 0));
  inputs[input_count++] =
      g.UseOperand(selector->input_at(node, 1), operand_mode);

  if (cont->IsDeoptimize()) {
    // If we can deoptimize as a result of the binop, we need to make sure that
    // the deopt inputs are not overwritten by the binop result. One way
    // to achieve that is to declare the output register as same-as-first.
    outputs[output_count++] = g.DefineSameAsFirst(node);
  } else {
    outputs[output_count++] = g.DefineAsRegister(node);
  }

  DCHECK_NE(0u, input_count);
  DCHECK_NE(0u, output_count);
  DCHECK_GE(arraysize(inputs), input_count);
  DCHECK_GE(arraysize(outputs), output_count);

  selector->EmitWithContinuation(opcode, output_count, outputs, input_count,
                                 inputs, cont);
}

// Shared routine for multiple binary operations.
template <typename Adapter>
void VisitBinop(InstructionSelectorT<Adapter>* selector,
                typename Adapter::node_t node, InstructionCode opcode,
                ImmediateMode operand_mode) {
  FlagsContinuationT<Adapter> cont;
  VisitBinop<Adapter>(selector, node, opcode, operand_mode, &cont);
}

}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackSlot(node_t node) {
  StackSlotRepresentation rep = this->stack_slot_representation_of(node);
  int slot =
      frame_->AllocateSpillSlot(rep.size(), rep.alignment(), rep.is_tagged());
  OperandGenerator g(this);

  Emit(kArchStackSlot, g.DefineAsRegister(node),
       sequence()->AddImmediate(Constant(slot)), 0, nullptr);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitAbortCSADcheck(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kArchAbortCSADcheck, g.NoOutput(),
         g.UseFixed(this->input_at(node, 0), r4));
}

ArchOpcode SelectLoadOpcode(turboshaft::MemoryRepresentation loaded_rep,
                            turboshaft::RegisterRepresentation result_rep,
                            ImmediateMode* mode) {
  // NOTE: The meaning of `loaded_rep` = `MemoryRepresentation::AnyTagged()` is
  // we are loading a compressed tagged field, while `result_rep` =
  // `RegisterRepresentation::Tagged()` refers to an uncompressed tagged value.
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    *mode = kInt34Imm;
  } else {
    *mode = kInt16Imm;
  }
  switch (loaded_rep) {
    case MemoryRepresentation::Int8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kPPC_LoadWordS8;
    case MemoryRepresentation::Uint8():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kPPC_LoadWordU8;
    case MemoryRepresentation::Int16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kPPC_LoadWordS16;
    case MemoryRepresentation::Uint16():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kPPC_LoadWordU16;
    case MemoryRepresentation::Int32():
    case MemoryRepresentation::Uint32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word32());
      return kPPC_LoadWordU32;
    case MemoryRepresentation::Int64():
    case MemoryRepresentation::Uint64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Word64());
      if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
      return kPPC_LoadWord64;
    case MemoryRepresentation::Float16():
      UNIMPLEMENTED();
    case MemoryRepresentation::Float32():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float32());
      return kPPC_LoadFloat32;
    case MemoryRepresentation::Float64():
      DCHECK_EQ(result_rep, RegisterRepresentation::Float64());
      return kPPC_LoadDouble;
#ifdef V8_COMPRESS_POINTERS
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
      if (result_rep == RegisterRepresentation::Compressed()) {
        if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
        return kPPC_LoadWordS32;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kPPC_LoadDecompressTagged;
    case MemoryRepresentation::TaggedSigned():
      if (result_rep == RegisterRepresentation::Compressed()) {
        if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
        return kPPC_LoadWordS32;
      }
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      return kPPC_LoadDecompressTaggedSigned;
#else
      USE(result_rep);
    case MemoryRepresentation::AnyTagged():
    case MemoryRepresentation::TaggedPointer():
    case MemoryRepresentation::TaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
      return kPPC_LoadWord64;
#endif
    case MemoryRepresentation::AnyUncompressedTagged():
    case MemoryRepresentation::UncompressedTaggedPointer():
    case MemoryRepresentation::UncompressedTaggedSigned():
      DCHECK_EQ(result_rep, RegisterRepresentation::Tagged());
      if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
      return kPPC_LoadWord64;
    case MemoryRepresentation::SandboxedPointer():
      return kPPC_LoadDecodeSandboxedPointer;
    case MemoryRepresentation::Simd128():
      DCHECK_EQ(result_rep, RegisterRepresentation::Simd128());
      // Vectors do not support MRI mode, only MRR is available.
      *mode = kNoImmediate;
      return kPPC_LoadSimd128;
    case MemoryRepresentation::ProtectedPointer():
    case MemoryRepresentation::IndirectPointer():
    case MemoryRepresentation::Simd256():
      UNREACHABLE();
  }
}

ArchOpcode SelectLoadOpcode(LoadRepresentation load_rep, ImmediateMode* mode) {
  if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
    *mode = kInt34Imm;
  } else {
    *mode = kInt16Imm;
  }
  switch (load_rep.representation()) {
    case MachineRepresentation::kFloat32:
      return kPPC_LoadFloat32;
    case MachineRepresentation::kFloat64:
      return kPPC_LoadDouble;
    case MachineRepresentation::kBit:  // Fall through.
    case MachineRepresentation::kWord8:
      return load_rep.IsSigned() ? kPPC_LoadWordS8 : kPPC_LoadWordU8;
    case MachineRepresentation::kWord16:
      return load_rep.IsSigned() ? kPPC_LoadWordS16 : kPPC_LoadWordU16;
    case MachineRepresentation::kWord32:
      return kPPC_LoadWordU32;
    case MachineRepresentation::kCompressedPointer:  // Fall through.
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
      return kPPC_LoadWordS32;
#else
      UNREACHABLE();
#endif
      case MachineRepresentation::kIndirectPointer:
        UNREACHABLE();
      case MachineRepresentation::kSandboxedPointer:
        return kPPC_LoadDecodeSandboxedPointer;
#ifdef V8_COMPRESS_POINTERS
      case MachineRepresentation::kTaggedSigned:
        return kPPC_LoadDecompressTaggedSigned;
      case MachineRepresentation::kTaggedPointer:
        return kPPC_LoadDecompressTagged;
      case MachineRepresentation::kTagged:
        return kPPC_LoadDecompressTagged;
#else
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:         // Fall through.
#endif
      case MachineRepresentation::kWord64:
        if (*mode != kInt34Imm) *mode = kInt16Imm_4ByteAligned;
        return kPPC_LoadWord64;
      case MachineRepresentation::kSimd128:
        // Vectors do not support MRI mode, only MRR is available.
        *mode = kNoImmediate;
        return kPPC_LoadSimd128;
      case MachineRepresentation::kFloat16:
        UNIMPLEMENTED();
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
  }
}

static void VisitLoadCommon(InstructionSelectorT<TurboshaftAdapter>* selector,
                            TurboshaftAdapter::node_t node, ImmediateMode mode,
                            InstructionCode opcode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = TurboshaftAdapter::node_t;
  PPCOperandGeneratorT<TurboshaftAdapter> g(selector);
  auto load_view = selector->load_view(node);
  node_t base = load_view.base();
  node_t offset = load_view.index();

  bool is_atomic = load_view.is_atomic();

  if (selector->is_load_root_register(base)) {
    selector->Emit(opcode |= AddressingModeField::encode(kMode_Root),
                   g.DefineAsRegister(node), g.UseRegister(offset),
                   g.UseImmediate(is_atomic));
  } else if (g.CanBeImmediate(offset, mode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(offset), g.UseImmediate(is_atomic));
  } else if (g.CanBeImmediate(base, mode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), g.UseRegister(offset),
                   g.UseImmediate(base), g.UseImmediate(is_atomic));
  } else {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRR),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseRegister(offset), g.UseImmediate(is_atomic));
  }
}

static void VisitLoadCommon(InstructionSelectorT<TurbofanAdapter>* selector,
                            TurbofanAdapter::node_t node, ImmediateMode mode,
                            InstructionCode opcode) {
  using node_t = TurbofanAdapter::node_t;
  PPCOperandGeneratorT<TurbofanAdapter> g(selector);
  auto load_view = selector->load_view(node);
  node_t base = load_view.base();
  node_t offset = load_view.index();

  bool is_atomic = load_view.is_atomic();

  if (selector->is_load_root_register(base)) {
    selector->Emit(opcode |= AddressingModeField::encode(kMode_Root),
                   g.DefineAsRegister(node), g.UseRegister(offset),
                   g.UseImmediate(is_atomic));
  } else if (g.CanBeImmediate(offset, mode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseImmediate(offset), g.UseImmediate(is_atomic));
  } else if (g.CanBeImmediate(base, mode)) {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                   g.DefineAsRegister(node), g.UseRegister(offset),
                   g.UseImmediate(base), g.UseImmediate(is_atomic));
  } else {
    selector->Emit(opcode | AddressingModeField::encode(kMode_MRR),
                   g.DefineAsRegister(node), g.UseRegister(base),
                   g.UseRegister(offset), g.UseImmediate(is_atomic));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  typename Adapter::LoadView load_view = this->load_view(node);
  ImmediateMode mode;
  if constexpr (Adapter::IsTurboshaft) {
    InstructionCode opcode = SelectLoadOpcode(load_view.ts_loaded_rep(),
                                              load_view.ts_result_rep(), &mode);
    VisitLoadCommon(this, node, mode, opcode);
  } else {
    InstructionCode opcode = SelectLoadOpcode(load_view.loaded_rep(), &mode);
    VisitLoadCommon(this, node, mode, opcode);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

void VisitStoreCommon(InstructionSelectorT<TurboshaftAdapter>* selector,
                      TurboshaftAdapter::node_t node,
                      StoreRepresentation store_rep,
                      std::optional<AtomicMemoryOrder> atomic_order) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  using node_t = TurboshaftAdapter::node_t;
  PPCOperandGeneratorT<TurboshaftAdapter> g(selector);
  auto store_view = selector->store_view(node);
  node_t base = store_view.base();
  node_t offset = selector->value(store_view.index());
  node_t value = store_view.value();
  bool is_atomic = store_view.is_atomic();

  MachineRepresentation rep = store_rep.representation();
  WriteBarrierKind write_barrier_kind = kNoWriteBarrier;

  if (!is_atomic) {
    write_barrier_kind = store_rep.write_barrier_kind();
  }

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedOrIndirectPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedOrIndirectPointer(rep));
    // Uncompressed stores should not happen if we need a write barrier.
    CHECK((store_view.ts_stored_rep() !=
           MemoryRepresentation::AnyUncompressedTagged()) &&
          (store_view.ts_stored_rep() !=
           MemoryRepresentation::UncompressedTaggedPointer()) &&
          (store_view.ts_stored_rep() !=
           MemoryRepresentation::UncompressedTaggedPointer()));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    // OutOfLineRecordWrite uses the offset in an 'add' instruction as well as
    // for the store itself, so we must check compatibility with both.
    if (g.CanBeImmediate(offset, kInt16Imm)
        && g.CanBeImmediate(offset, kInt16Imm_4ByteAligned)
    ) {
      inputs[input_count++] = g.UseImmediate(offset);
      addressing_mode = kMode_MRI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(offset);
      addressing_mode = kMode_MRR;
    }
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code;
    if (rep == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store_view.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate(static_cast<int64_t>(tag));
    } else {
      code = kArchStoreWithWriteBarrier;
    }
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    CHECK_EQ(is_atomic, false);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    ImmediateMode mode;
    if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
      mode = kInt34Imm;
    } else {
      mode = kInt16Imm;
    }
    switch (store_view.ts_stored_rep()) {
      case MemoryRepresentation::Int8():
      case MemoryRepresentation::Uint8():
        opcode = kPPC_StoreWord8;
        break;
      case MemoryRepresentation::Int16():
      case MemoryRepresentation::Uint16():
        opcode = kPPC_StoreWord16;
        break;
      case MemoryRepresentation::Int32():
      case MemoryRepresentation::Uint32(): {
        opcode = kPPC_StoreWord32;
        const Operation& reverse_op = selector->Get(value);
        if (reverse_op.Is<Opmask::kWord32ReverseBytes>()) {
          opcode = kPPC_StoreByteRev32;
          value = selector->input_at(value, 0);
          mode = kNoImmediate;
        }
        break;
      }
      case MemoryRepresentation::Int64():
      case MemoryRepresentation::Uint64(): {
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreWord64;
        const Operation& reverse_op = selector->Get(value);
        if (reverse_op.Is<Opmask::kWord64ReverseBytes>()) {
          opcode = kPPC_StoreByteRev64;
          value = selector->input_at(value, 0);
          mode = kNoImmediate;
        }
        break;
      }
      case MemoryRepresentation::Float16():
        UNIMPLEMENTED();
      case MemoryRepresentation::Float32():
        opcode = kPPC_StoreFloat32;
        break;
      case MemoryRepresentation::Float64():
        opcode = kPPC_StoreDouble;
        break;
      case MemoryRepresentation::AnyTagged():
      case MemoryRepresentation::TaggedPointer():
      case MemoryRepresentation::TaggedSigned():
        if (mode != kInt34Imm) mode = kInt16Imm;
        opcode = kPPC_StoreCompressTagged;
        break;
      case MemoryRepresentation::AnyUncompressedTagged():
      case MemoryRepresentation::UncompressedTaggedPointer():
      case MemoryRepresentation::UncompressedTaggedSigned():
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreWord64;
        break;
      case MemoryRepresentation::ProtectedPointer():
        // We never store directly to protected pointers from generated code.
        UNREACHABLE();
      case MemoryRepresentation::IndirectPointer():
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreIndirectPointer;
        break;
      case MemoryRepresentation::SandboxedPointer():
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreEncodeSandboxedPointer;
        break;
      case MemoryRepresentation::Simd128():
        opcode = kPPC_StoreSimd128;
        // Vectors do not support MRI mode, only MRR is available.
        mode = kNoImmediate;
        break;
      case MemoryRepresentation::Simd256():
        UNREACHABLE();
    }

    if (selector->is_load_root_register(base)) {
      selector->Emit(opcode | AddressingModeField::encode(kMode_Root),
                     g.NoOutput(), g.UseRegister(offset), g.UseRegister(value),
                     g.UseImmediate(is_atomic));
    } else if (g.CanBeImmediate(offset, mode)) {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.NoOutput(), g.UseRegister(base), g.UseImmediate(offset),
                     g.UseRegister(value), g.UseImmediate(is_atomic));
    } else if (g.CanBeImmediate(base, mode)) {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.NoOutput(), g.UseRegister(offset), g.UseImmediate(base),
                     g.UseRegister(value), g.UseImmediate(is_atomic));
    } else {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRR),
                     g.NoOutput(), g.UseRegister(base), g.UseRegister(offset),
                     g.UseRegister(value), g.UseImmediate(is_atomic));
    }
  }
}

void VisitStoreCommon(InstructionSelectorT<TurbofanAdapter>* selector,
                      TurbofanAdapter::node_t node,
                      StoreRepresentation store_rep,
                      std::optional<AtomicMemoryOrder> atomic_order) {
  using node_t = TurbofanAdapter::node_t;
  PPCOperandGeneratorT<TurbofanAdapter> g(selector);
  auto store_view = selector->store_view(node);
  node_t base = store_view.base();
  node_t offset = selector->value(store_view.index());
  node_t value = store_view.value();
  bool is_atomic = store_view.is_atomic();

  MachineRepresentation rep = store_rep.representation();
  WriteBarrierKind write_barrier_kind = kNoWriteBarrier;

  if (!is_atomic) {
    write_barrier_kind = store_rep.write_barrier_kind();
  }

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedOrIndirectPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedOrIndirectPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    // OutOfLineRecordWrite uses the offset in an 'add' instruction as well as
    // for the store itself, so we must check compatibility with both.
    if (g.CanBeImmediate(offset, kInt16Imm)
        && g.CanBeImmediate(offset, kInt16Imm_4ByteAligned)
            ) {
      inputs[input_count++] = g.UseImmediate(offset);
      addressing_mode = kMode_MRI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(offset);
      addressing_mode = kMode_MRR;
    }
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionOperand temps[] = {g.TempRegister(), g.TempRegister()};
    size_t const temp_count = arraysize(temps);
    InstructionCode code;
    if (rep == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store_view.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate(static_cast<int64_t>(tag));
    } else {
      code = kArchStoreWithWriteBarrier;
    }
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    CHECK_EQ(is_atomic, false);
    selector->Emit(code, 0, nullptr, input_count, inputs, temp_count, temps);
  } else {
    ArchOpcode opcode;
    ImmediateMode mode;
    if (CpuFeatures::IsSupported(PPC_10_PLUS)) {
      mode = kInt34Imm;
    } else {
      mode = kInt16Imm;
    }
    switch (rep) {
      case MachineRepresentation::kFloat32:
        opcode = kPPC_StoreFloat32;
        break;
      case MachineRepresentation::kFloat64:
        opcode = kPPC_StoreDouble;
        break;
      case MachineRepresentation::kBit:  // Fall through.
      case MachineRepresentation::kWord8:
        opcode = kPPC_StoreWord8;
        break;
      case MachineRepresentation::kWord16:
        opcode = kPPC_StoreWord16;
        break;
      case MachineRepresentation::kWord32: {
        opcode = kPPC_StoreWord32;
          NodeMatcher m(value);
          if (m.IsWord32ReverseBytes()) {
            opcode = kPPC_StoreByteRev32;
            value = selector->input_at(value, 0);
            mode = kNoImmediate;
          }
        break;
      }
      case MachineRepresentation::kCompressedPointer:  // Fall through.
      case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
        if (mode != kInt34Imm) mode = kInt16Imm;
        opcode = kPPC_StoreCompressTagged;
        break;
#else
        UNREACHABLE();
#endif
      case MachineRepresentation::kIndirectPointer:
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreIndirectPointer;
        break;
      case MachineRepresentation::kSandboxedPointer:
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreEncodeSandboxedPointer;
        break;
      case MachineRepresentation::kTaggedSigned:   // Fall through.
      case MachineRepresentation::kTaggedPointer:  // Fall through.
      case MachineRepresentation::kTagged:
        if (mode != kInt34Imm) mode = kInt16Imm_4ByteAligned;
        opcode = kPPC_StoreCompressTagged;
        break;
      case MachineRepresentation::kWord64: {
        opcode = kPPC_StoreWord64;
        if (mode != kInt34Imm) {
          mode = kInt16Imm_4ByteAligned;
        }
        NodeMatcher m(value);
        if (m.IsWord64ReverseBytes()) {
          opcode = kPPC_StoreByteRev64;
          value = selector->input_at(value, 0);
          mode = kNoImmediate;
        }
        break;
      }
      case MachineRepresentation::kSimd128:
        opcode = kPPC_StoreSimd128;
        // Vectors do not support MRI mode, only MRR is available.
        mode = kNoImmediate;
        break;
      case MachineRepresentation::kFloat16:
        UNIMPLEMENTED();
      case MachineRepresentation::kProtectedPointer:  // Fall through.
      case MachineRepresentation::kSimd256:  // Fall through.
      case MachineRepresentation::kMapWord:  // Fall through.
      case MachineRepresentation::kNone:
        UNREACHABLE();
    }

    if (selector->is_load_root_register(base)) {
      selector->Emit(opcode | AddressingModeField::encode(kMode_Root),
                     g.NoOutput(), g.UseRegister(offset), g.UseRegister(value),
                     g.UseImmediate(is_atomic));
    } else if (g.CanBeImmediate(offset, mode)) {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.NoOutput(), g.UseRegister(base), g.UseImmediate(offset),
                     g.UseRegister(value), g.UseImmediate(is_atomic));
    } else if (g.CanBeImmediate(base, mode)) {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRI),
                     g.NoOutput(), g.UseRegister(offset), g.UseImmediate(base),
                     g.UseRegister(value), g.UseImmediate(is_atomic));
    } else {
      selector->Emit(opcode | AddressingModeField::encode(kMode_MRR),
                     g.NoOutput(), g.UseRegister(base), g.UseRegister(offset),
                     g.UseRegister(value), g.UseImmediate(is_atomic));
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(node_t node) {
  VisitStoreCommon(this, node, this->store_view(node).stored_rep(),
                   std::nullopt);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  // TODO(eholk)
  UNIMPLEMENTED();
}

// Architecture supports unaligned access, therefore VisitLoad is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedLoad(node_t node) {
  UNREACHABLE();
}

// Architecture supports unaligned access, therefore VisitStore is used instead
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitUnalignedStore(node_t node) {
  UNREACHABLE();
}

static void VisitLogical(InstructionSelectorT<TurboshaftAdapter>* selector,
                         turboshaft::OpIndex node, ArchOpcode opcode,
                         bool left_can_cover, bool right_can_cover,
                         ImmediateMode imm_mode) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(selector);
  const WordBinopOp& logical_op = selector->Get(node).Cast<WordBinopOp>();
  const Operation& lhs = selector->Get(logical_op.left());
  const Operation& rhs = selector->Get(logical_op.right());

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kPPC_And:
      inv_opcode = kPPC_AndComplement;
      break;
    case kPPC_Or:
      inv_opcode = kPPC_OrComplement;
      break;
    default:
      UNREACHABLE();
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if (lhs.Is<Opmask::kBitwiseXor>() && left_can_cover) {
    const WordBinopOp& xor_op = lhs.Cast<WordBinopOp>();
    int64_t xor_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.right()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  // Select Logical(x, ~y) for Logical(x, Xor(y, -1)).
  if (rhs.Is<Opmask::kBitwiseXor>() && right_can_cover) {
    const WordBinopOp& xor_op = rhs.Cast<WordBinopOp>();
    int64_t xor_rhs_val;
    if (selector->MatchSignedIntegralConstant(xor_op.right(), &xor_rhs_val) &&
        xor_rhs_val == -1) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(logical_op.left()),
                     g.UseRegister(xor_op.left()));
      return;
    }
  }

  VisitBinop<TurboshaftAdapter>(selector, node, opcode, imm_mode);
}

template <typename Adapter, typename Matcher>
static void VisitLogical(InstructionSelectorT<Adapter>* selector, Node* node,
                         Matcher* m, ArchOpcode opcode, bool left_can_cover,
                         bool right_can_cover, ImmediateMode imm_mode) {
  PPCOperandGeneratorT<Adapter> g(selector);

  // Map instruction to equivalent operation with inverted right input.
  ArchOpcode inv_opcode = opcode;
  switch (opcode) {
    case kPPC_And:
      inv_opcode = kPPC_AndComplement;
      break;
    case kPPC_Or:
      inv_opcode = kPPC_OrComplement;
      break;
    default:
      UNREACHABLE();
  }

  // Select Logical(y, ~x) for Logical(Xor(x, -1), y).
  if ((m->left().IsWord32Xor() || m->left().IsWord64Xor()) && left_can_cover) {
    Matcher mleft(m->left().node());
    if (mleft.right().Is(-1)) {
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(m->right().node()),
                     g.UseRegister(mleft.left().node()));
      return;
    }
  }

  // Select Logical(x, ~y) for Logical(x, Xor(y, -1)).
  if ((m->right().IsWord32Xor() || m->right().IsWord64Xor()) &&
      right_can_cover) {
    Matcher mright(m->right().node());
    if (mright.right().Is(-1)) {
      // TODO(all): support shifted operand on right.
      selector->Emit(inv_opcode, g.DefineAsRegister(node),
                     g.UseRegister(m->left().node()),
                     g.UseRegister(mright.left().node()));
      return;
    }
  }

  VisitBinop<Adapter>(selector, node, opcode, imm_mode);
}

static inline bool IsContiguousMask32(uint32_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros32(value);
  int mask_lsb = base::bits::CountTrailingZeros32(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 32))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}

static inline bool IsContiguousMask64(uint64_t value, int* mb, int* me) {
  int mask_width = base::bits::CountPopulation(value);
  int mask_msb = base::bits::CountLeadingZeros64(value);
  int mask_lsb = base::bits::CountTrailingZeros64(value);
  if ((mask_width == 0) || (mask_msb + mask_width + mask_lsb != 64))
    return false;
  *mb = mask_lsb + mask_width - 1;
  *me = mask_lsb;
  return true;
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  int mb = 0;
  int me = 0;
  if (is_integer_constant(bitwise_and.right()) &&
      IsContiguousMask32(integer_constant(bitwise_and.right()), &mb, &me)) {
    int sh = 0;
    node_t left = bitwise_and.left();
    const Operation& lhs = Get(left);
    if ((lhs.Is<Opmask::kWord32ShiftRightLogical>() ||
         lhs.Is<Opmask::kWord32ShiftLeft>()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rlwinm
      int32_t shift_by;
      const ShiftOp& shift_op = lhs.Cast<ShiftOp>();
      if (MatchIntegralWord32Constant(shift_op.right(), &shift_by) &&
          base::IsInRange(shift_by, 0, 31)) {
        left = shift_op.left();
        sh = integer_constant(shift_op.right());
        if (lhs.Is<Opmask::kWord32ShiftRightLogical>()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 31 - sh) mb = 31 - sh;
          sh = (32 - sh) & 0x1F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node), g.UseRegister(left),
           g.TempImmediate(sh), g.TempImmediate(mb), g.TempImmediate(me));
      return;
    }
  }
  VisitLogical(this, node, kPPC_And, CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kInt16Imm_Unsigned);
}

// TODO(mbrandy): Absorb rotate-right into rlwinm?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32And(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  Int32BinopMatcher m(node);
  int mb = 0;
  int me = 0;
  if (m.right().HasResolvedValue() &&
      IsContiguousMask32(m.right().ResolvedValue(), &mb, &me)) {
    int sh = 0;
    Node* left = m.left().node();
    if ((m.left().IsWord32Shr() || m.left().IsWord32Shl()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rlwinm
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().IsInRange(0, 31)) {
        left = mleft.left().node();
        sh = mleft.right().ResolvedValue();
        if (m.left().IsWord32Shr()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 31 - sh) mb = 31 - sh;
          sh = (32 - sh) & 0x1F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node), g.UseRegister(left),
           g.TempImmediate(sh), g.TempImmediate(mb), g.TempImmediate(me));
      return;
    }
  }
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kPPC_And, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  PPCOperandGeneratorT<TurboshaftAdapter> g(this);

  const WordBinopOp& bitwise_and = Get(node).Cast<WordBinopOp>();
  int mb = 0;
  int me = 0;
  if (is_integer_constant(bitwise_and.right()) &&
      IsContiguousMask64(integer_constant(bitwise_and.right()), &mb, &me)) {
    int sh = 0;
    node_t left = bitwise_and.left();
    const Operation& lhs = Get(left);
    if ((lhs.Is<Opmask::kWord64ShiftRightLogical>() ||
         lhs.Is<Opmask::kWord64ShiftLeft>()) &&
        CanCover(node, left)) {
      // Try to absorb left/right shift into rldic
      int64_t shift_by;
      const ShiftOp& shift_op = lhs.Cast<ShiftOp>();
      if (MatchIntegralWord64Constant(shift_op.right(), &shift_by) &&
          base::IsInRange(shift_by, 0, 63)) {
        left = shift_op.left();
        sh = integer_constant(shift_op.right());
        if (lhs.Is<Opmask::kWord64ShiftRightLogical>()) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
        } else {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
        }
      }
    }
    if (mb >= me) {
      bool match = false;
      ArchOpcode opcode;
      int mask;
      if (me == 0) {
        match = true;
        opcode = kPPC_RotLeftAndClearLeft64;
        mask = mb;
      } else if (mb == 63) {
        match = true;
        opcode = kPPC_RotLeftAndClearRight64;
        mask = me;
      } else if (sh && me <= sh && lhs.Is<Opmask::kWord64ShiftLeft>()) {
        match = true;
        opcode = kPPC_RotLeftAndClear64;
        mask = mb;
      }
      if (match) {
        Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
             g.TempImmediate(sh), g.TempImmediate(mask));
        return;
      }
    }
  }
  VisitLogical(this, node, kPPC_And, CanCover(node, bitwise_and.left()),
               CanCover(node, bitwise_and.right()), kInt16Imm_Unsigned);
}

// TODO(mbrandy): Absorb rotate-right into rldic?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64And(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    int mb = 0;
    int me = 0;
    if (m.right().HasResolvedValue() &&
        IsContiguousMask64(m.right().ResolvedValue(), &mb, &me)) {
      int sh = 0;
      Node* left = m.left().node();
      if ((m.left().IsWord64Shr() || m.left().IsWord64Shl()) &&
          CanCover(node, left)) {
        // Try to absorb left/right shift into rldic
        Int64BinopMatcher mleft(m.left().node());
        if (mleft.right().IsInRange(0, 63)) {
          left = mleft.left().node();
          sh = mleft.right().ResolvedValue();
          if (m.left().IsWord64Shr()) {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (mb > 63 - sh) mb = 63 - sh;
            sh = (64 - sh) & 0x3F;
          } else {
            // Adjust the mask such that it doesn't include any rotated bits.
            if (me < sh) me = sh;
          }
        }
      }
      if (mb >= me) {
        bool match = false;
        ArchOpcode opcode;
        int mask;
        if (me == 0) {
          match = true;
          opcode = kPPC_RotLeftAndClearLeft64;
          mask = mb;
        } else if (mb == 63) {
          match = true;
          opcode = kPPC_RotLeftAndClearRight64;
          mask = me;
        } else if (sh && me <= sh && m.left().IsWord64Shl()) {
          match = true;
          opcode = kPPC_RotLeftAndClear64;
          mask = mb;
        }
        if (match) {
          Emit(opcode, g.DefineAsRegister(node), g.UseRegister(left),
               g.TempImmediate(sh), g.TempImmediate(mask));
          return;
        }
      }
    }
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kPPC_And, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, node, kPPC_Or, CanCover(node, op.left()),
                 CanCover(node, op.right()), kInt16Imm_Unsigned);
  } else {
    Int32BinopMatcher m(node);
    VisitLogical<Adapter, Int32BinopMatcher>(
        this, node, &m, kPPC_Or, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& op = this->Get(node).template Cast<WordBinopOp>();
    VisitLogical(this, node, kPPC_Or, CanCover(node, op.left()),
                 CanCover(node, op.right()), kInt16Imm_Unsigned);
  } else {
    Int64BinopMatcher m(node);
    VisitLogical<Adapter, Int64BinopMatcher>(
        this, node, &m, kPPC_Or, CanCover(node, m.left().node()),
        CanCover(node, m.right().node()), kInt16Imm_Unsigned);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& bitwise_xor =
        this->Get(node).template Cast<WordBinopOp>();
    int32_t mask;
    if (this->MatchIntegralWord32Constant(bitwise_xor.right(), &mask) &&
        mask == -1) {
      Emit(kPPC_Not, g.DefineAsRegister(node),
           g.UseRegister(bitwise_xor.left()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  } else {
    Int32BinopMatcher m(node);
    if (m.right().Is(-1)) {
      Emit(kPPC_Not, g.DefineAsRegister(node), g.UseRegister(m.left().node()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStackPointerGreaterThan(
    node_t node, FlagsContinuation* cont) {
  StackCheckKind kind;
  node_t value;
  if constexpr (Adapter::IsTurboshaft) {
    const auto& op =
        this->turboshaft_graph()
            ->Get(node)
            .template Cast<turboshaft::StackPointerGreaterThanOp>();
    kind = op.kind;
    value = op.stack_limit();
  } else {
    kind = StackCheckKindOf(node->op());
    value = node->InputAt(0);
  }
  InstructionCode opcode =
      kArchStackPointerGreaterThan | MiscField::encode(static_cast<int>(kind));

  PPCOperandGeneratorT<Adapter> g(this);

  // No outputs.
  InstructionOperand* const outputs = nullptr;
  const int output_count = 0;

  // Applying an offset to this stack check requires a temp register. Offsets
  // are only applied to the first stack check. If applying an offset, we must
  // ensure the input and temp registers do not alias, thus kUniqueRegister.
  InstructionOperand temps[] = {g.TempRegister()};
  const int temp_count = (kind == StackCheckKind::kJSFunctionEntry) ? 1 : 0;
  const auto register_mode = (kind == StackCheckKind::kJSFunctionEntry)
                                 ? OperandGenerator::kUniqueRegister
                                 : OperandGenerator::kRegister;

  InstructionOperand inputs[] = {g.UseRegisterWithMode(value, register_mode)};
  static constexpr int input_count = arraysize(inputs);

  EmitWithContinuation(opcode, output_count, outputs, input_count, inputs,
                       temp_count, temps, cont);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const WordBinopOp& bitwise_xor =
        this->Get(node).template Cast<WordBinopOp>();
    int64_t mask;
    if (this->MatchIntegralWord64Constant(bitwise_xor.right(), &mask) &&
        mask == -1) {
      Emit(kPPC_Not, g.DefineAsRegister(node),
           g.UseRegister(bitwise_xor.left()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  } else {
    Int64BinopMatcher m(node);
    if (m.right().Is(-1)) {
      Emit(kPPC_Not, g.DefineAsRegister(node), g.UseRegister(m.left().node()));
    } else {
      VisitBinop<Adapter>(this, node, kPPC_Xor, kInt16Imm_Unsigned);
    }
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shl(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shl = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shl.left());
    if (lhs.Is<Opmask::kWord32BitwiseAnd>() &&
        this->is_integer_constant(shl.right()) &&
        base::IsInRange(this->integer_constant(shl.right()), 0, 31)) {
      int sh = this->integer_constant(shl.right());
      int mb;
      int me;
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (this->is_integer_constant(bitwise_and.right()) &&
          IsContiguousMask32(this->integer_constant(bitwise_and.right()) << sh,
                             &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (me < sh) me = sh;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftLeft32, node, kShift32Imm);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32And() && m.right().IsInRange(0, 31)) {
      // Try to absorb logical-and into rlwinm
      Int32BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask32(mleft.right().ResolvedValue() << sh, &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (me < sh) me = sh;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftLeft32, node, kShift32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const ShiftOp& shl = this->Get(node).template Cast<ShiftOp>();
      const Operation& lhs = this->Get(shl.left());
      if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
          this->is_integer_constant(shl.right()) &&
          base::IsInRange(this->integer_constant(shl.right()), 0, 63)) {
        int sh = this->integer_constant(shl.right());
        int mb;
        int me;
        const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
        if (this->is_integer_constant(bitwise_and.right()) &&
            IsContiguousMask64(
                this->integer_constant(bitwise_and.right()) << sh, &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            } else if (sh && me <= sh) {
              match = true;
              opcode = kPPC_RotLeftAndClear64;
              mask = mb;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftLeft64, node, kShift64Imm);
    } else {
      Int64BinopMatcher m(node);
      // TODO(mbrandy): eliminate left sign extension if right >= 32
      if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
        // Try to absorb logical-and into rldic
        Int64BinopMatcher mleft(m.left().node());
        int sh = m.right().ResolvedValue();
        int mb;
        int me;
        if (mleft.right().HasResolvedValue() &&
            IsContiguousMask64(mleft.right().ResolvedValue() << sh, &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (me < sh) me = sh;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            } else if (sh && me <= sh) {
              match = true;
              opcode = kPPC_RotLeftAndClear64;
              mask = mb;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftLeft64, node, kShift64Imm);
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Shr(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shr.left());
    if (lhs.Is<Opmask::kWord32BitwiseAnd>() &&
        this->is_integer_constant(shr.right()) &&
        base::IsInRange(this->integer_constant(shr.right()), 0, 31)) {
      int sh = this->integer_constant(shr.right());
      int mb;
      int me;
      const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
      if (this->is_integer_constant(bitwise_and.right()) &&
          IsContiguousMask32(
              static_cast<uint32_t>(
                  this->integer_constant(bitwise_and.right()) >> sh),
              &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (mb > 31 - sh) mb = 31 - sh;
        sh = (32 - sh) & 0x1F;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRight32, node, kShift32Imm);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32And() && m.right().IsInRange(0, 31)) {
      // Try to absorb logical-and into rlwinm
      Int32BinopMatcher mleft(m.left().node());
      int sh = m.right().ResolvedValue();
      int mb;
      int me;
      if (mleft.right().HasResolvedValue() &&
          IsContiguousMask32((uint32_t)(mleft.right().ResolvedValue()) >> sh,
                             &mb, &me)) {
        // Adjust the mask such that it doesn't include any rotated bits.
        if (mb > 31 - sh) mb = 31 - sh;
        sh = (32 - sh) & 0x1F;
        if (mb >= me) {
          Emit(kPPC_RotLeftAndMask32, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
               g.TempImmediate(mb), g.TempImmediate(me));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRight32, node, kShift32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shr(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      const ShiftOp& shr = this->Get(node).template Cast<ShiftOp>();
      const Operation& lhs = this->Get(shr.left());
      if (lhs.Is<Opmask::kWord64BitwiseAnd>() &&
          this->is_integer_constant(shr.right()) &&
          base::IsInRange(this->integer_constant(shr.right()), 0, 63)) {
        int sh = this->integer_constant(shr.right());
        int mb;
        int me;
        const WordBinopOp& bitwise_and = lhs.Cast<WordBinopOp>();
        if (this->is_integer_constant(bitwise_and.right()) &&
            IsContiguousMask64(
                static_cast<uint64_t>(
                    this->integer_constant(bitwise_and.right()) >> sh),
                &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(bitwise_and.left()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftRight64, node, kShift64Imm);
    } else {
      Int64BinopMatcher m(node);
      if (m.left().IsWord64And() && m.right().IsInRange(0, 63)) {
        // Try to absorb logical-and into rldic
        Int64BinopMatcher mleft(m.left().node());
        int sh = m.right().ResolvedValue();
        int mb;
        int me;
        if (mleft.right().HasResolvedValue() &&
            IsContiguousMask64((uint64_t)(mleft.right().ResolvedValue()) >> sh,
                               &mb, &me)) {
          // Adjust the mask such that it doesn't include any rotated bits.
          if (mb > 63 - sh) mb = 63 - sh;
          sh = (64 - sh) & 0x3F;
          if (mb >= me) {
            bool match = false;
            ArchOpcode opcode;
            int mask;
            if (me == 0) {
              match = true;
              opcode = kPPC_RotLeftAndClearLeft64;
              mask = mb;
            } else if (mb == 63) {
              match = true;
              opcode = kPPC_RotLeftAndClearRight64;
              mask = me;
            }
            if (match) {
              Emit(opcode, g.DefineAsRegister(node),
                   g.UseRegister(mleft.left().node()), g.TempImmediate(sh),
                   g.TempImmediate(mask));
              return;
            }
          }
        }
      }
      VisitRRO(this, kPPC_ShiftRight64, node, kShift64Imm);
    }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Sar(node_t node) {
  PPCOperandGeneratorT<Adapter> g(this);
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& sar = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(sar.left());
    if (CanCover(node, sar.left()) && lhs.Is<Opmask::kWord32ShiftLeft>()) {
      const ShiftOp& shl = lhs.Cast<ShiftOp>();
      if (this->is_integer_constant(sar.right()) &&
          this->is_integer_constant(shl.right())) {
        uint32_t sar_by = this->integer_constant(sar.right());
        uint32_t shl_by = this->integer_constant(shl.right());
        if ((sar_by == shl_by) && (sar_by == 16)) {
          Emit(kPPC_ExtendSignWord16, g.DefineAsRegister(node),
               g.UseRegister(shl.left()));
          return;
        } else if ((sar_by == shl_by) && (sar_by == 24)) {
          Emit(kPPC_ExtendSignWord8, g.DefineAsRegister(node),
               g.UseRegister(shl.left()));
          return;
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRightAlg32, node, kShift32Imm);
  } else {
    Int32BinopMatcher m(node);
    // Replace with sign extension for (x << K) >> K where K is 16 or 24.
    if (CanCover(node, m.left().node()) && m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().Is(16) && m.right().Is(16)) {
        Emit(kPPC_ExtendSignWord16, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()));
        return;
      } else if (mleft.right().Is(24) && m.right().Is(24)) {
        Emit(kPPC_ExtendSignWord8, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()));
        return;
      }
    }
    VisitRRO(this, kPPC_ShiftRightAlg32, node, kShift32Imm);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    if constexpr (Adapter::IsTurboshaft) {
      using namespace turboshaft;  // NOLINT(build/namespaces)
      DCHECK(this->Get(node).template Cast<ShiftOp>().IsRightShift());
      const ShiftOp& shift = this->Get(node).template Cast<ShiftOp>();
      const Operation& lhs = this->Get(shift.left());
      int64_t constant_rhs;

      if (lhs.Is<LoadOp>() &&
          this->MatchIntegralWord64Constant(shift.right(), &constant_rhs) &&
          constant_rhs == 32 && this->CanCover(node, shift.left())) {
        // Just load and sign-extend the interesting 4 bytes instead. This
        // happens, for example, when we're loading and untagging SMIs.
        const LoadOp& load = lhs.Cast<LoadOp>();
        int64_t offset = 0;
        if (load.index().has_value()) {
          int64_t index_constant;
          if (this->MatchIntegralWord64Constant(load.index().value(),
                                                &index_constant)) {
            DCHECK_EQ(load.element_size_log2, 0);
            offset = index_constant;
          }
        } else {
          offset = load.offset;
        }
        offset = SmiWordOffset(offset);
        if (g.CanBeImmediate(offset, kInt16Imm_4ByteAligned)) {
          Emit(kPPC_LoadWordS32 | AddressingModeField::encode(kMode_MRI),
               g.DefineAsRegister(node), g.UseRegister(load.base()),
               g.TempImmediate(offset), g.UseImmediate(0));
          return;
        }
      }
    } else {
      Int64BinopMatcher m(node);
      if (CanCover(m.node(), m.left().node()) && m.left().IsLoad() &&
          m.right().Is(32)) {
        // Just load and sign-extend the interesting 4 bytes instead. This
        // happens, for example, when we're loading and untagging SMIs.
        BaseWithIndexAndDisplacement64Matcher mleft(m.left().node(),
                                                    AddressOption::kAllowAll);
        if (mleft.matches() && mleft.index() == nullptr) {
          int64_t offset = 0;
          Node* displacement = mleft.displacement();
          if (displacement != nullptr) {
            Int64Matcher mdisplacement(displacement);
            DCHECK(mdisplacement.HasResolvedValue());
            offset = mdisplacement.ResolvedValue();
          }
          offset = SmiWordOffset(offset);
          if (g.CanBeImmediate(offset, kInt16Imm_4ByteAligned)) {
            Emit(kPPC_LoadWordS32 | AddressingModeField::encode(kMode_MRI),
                 g.DefineAsRegister(node), g.UseRegister(mleft.base()),
                 g.TempImmediate(offset), g.UseImmediate(0));
            return;
          }
        }
      }
    }
    VisitRRO(this, kPPC_ShiftRightAlg64, node, kShift64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
    UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

// TODO(mbrandy): Absorb logical-and into rlwinm?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
    VisitRRO(this, kPPC_RotRight32, node, kShift32Imm);
}

// TODO(mbrandy): Absorb logical-and into rldic?
template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
    VisitRRO(this, kPPC_RotRight64, node, kShift64Imm);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Clz(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Cntlz32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Clz(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Cntlz64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Popcnt32, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Popcnt(node_t node) {
    PPCOperandGeneratorT<Adapter> g(this);
    Emit(kPPC_Popcnt64, g.DefineAsRegister(node),
         g.UseRegister(this->input_at(node, 0)));
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    PPCOperandGeneratorT<Adapter> g(this);
    InstructionOperand temp[] = {g.TempRegister()};
    node_t input = this->Get(node).input(0);
    const Operation& input_op = this->Get(input);
    if (CanCover(node, input) && input_op.Is<LoadOp>()) {
      auto load = this->load_view(input);
      LoadRepresentation load_rep = load.loaded_rep();
      if (load_rep.representation() == MachineRepresentation::kWord64) {
        node_t base = load.base();
        node_t offset = load.index();
        bool is_
"""


```