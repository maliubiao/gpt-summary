Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality in relation to JavaScript.

**1. Initial Skim and Identification of Core Components:**

The first step is to quickly read through the code, noting keywords and class names. Terms like `BytecodeArrayBuilder`, `Bytecode`, `Register`, `Label`, `Jump`, `Output`, and `ConstantPool` immediately jump out. The file name `bytecode-array-builder.cc` itself is a strong indicator of its purpose.

**2. Focus on the Central Class: `BytecodeArrayBuilder`:**

The class `BytecodeArrayBuilder` is clearly the core of this file. The constructor and methods within this class are the key to understanding its functionality.

**3. Analyzing the Constructor:**

The constructor takes parameters like `parameter_count`, `locals_count`, and `feedback_vector_spec`. These hint at the representation of a function's execution context. The initialization of `bytecode_array_writer_` and `constant_array_builder_` suggests the core tasks of building the bytecode array and managing constants. The presence of `register_optimizer_` indicates a potential optimization pass.

**4. Deciphering Key Methods and Their Roles:**

* **`Parameter()`, `Receiver()`, `Local()`:** These methods clearly relate to accessing variables within a function's scope. The naming is very self-explanatory.
* **`ToBytecodeArray()`:** This method is crucial. It's the point where the accumulated bytecode instructions are finalized and converted into a `BytecodeArray`.
* **`Output...()` methods (e.g., `OutputLdarRaw`, `OutputStarRaw`, `OutputAdd`, `OutputCallProperty`):**  These are the workhorses of the builder. They correspond to individual bytecode instructions. The names often directly reflect the operation (e.g., `Ldar` likely means "Load Accumulator Register").
* **`Create...Node()` methods:** These seem to create an intermediate representation of bytecode instructions before they are written.
* **`Bind()` methods:** These are related to labels and control flow, indicating the ability to jump to specific points in the bytecode.
* **`Jump...()` methods:**  These represent different conditional and unconditional jump instructions.
* **`Load...()` and `Store...()` methods:** These methods handle the loading and storing of values from various locations (globals, contexts, properties).
* **Methods related to literals (`LoadLiteral`) and constants (`GetConstantPoolEntry`):** These indicate the management of constant values used in the code.
* **Methods related to context (`CreateContext`, `PushContext`, `PopContext`):** These point to the handling of scope and variable access.
* **Methods related to function calls and object creation (`CallProperty`, `Construct`, `CreateObjectLiteral`):**  These represent the dynamic aspects of execution.

**5. Identifying the Relationship to JavaScript:**

The presence of terms like "global," "property," "context," "closure," "arguments," "RegExp," "array," and "object" strongly suggests a connection to JavaScript's execution model. The bytecode being built is clearly for *executing* JavaScript code.

**6. Connecting Bytecodes to JavaScript Constructs:**

Now the task is to map the identified bytecode operations to corresponding JavaScript syntax and behavior. This involves some educated guesswork and understanding of how JavaScript features are typically implemented.

* **Variable access:** `LoadGlobal`, `LoadContextSlot`, `LoadLookupSlot` relate to accessing variables in different scopes.
* **Assignments:** `StoreGlobal`, `StoreContextSlot`, `SetNamedProperty`, `SetKeyedProperty` relate to assigning values to variables and object properties.
* **Arithmetic and logical operations:** `OutputAdd`, `OutputSub`, `OutputLogicalNot`, etc., directly correspond to JavaScript operators.
* **Function calls:** `CallProperty`, `Construct` map to regular function calls and constructor invocations.
* **Object and array literals:** `CreateObjectLiteral`, `CreateArrayLiteral` correspond to the creation of these data structures.
* **Control flow:** `Jump`, `JumpIfTrue`, `JumpIfFalse` represent `if`, `else`, loops, and other control flow statements.
* **`this` keyword:** The `Receiver()` method likely relates to the `this` binding in JavaScript.
* **`arguments` object:**  `CreateArguments` handles the creation of the `arguments` object.
* **`try...catch`:** `MarkHandler`, `MarkTryBegin`, `MarkTryEnd` are related to exception handling.

**7. Constructing JavaScript Examples:**

Once the connections are established, it's relatively straightforward to create JavaScript code snippets that would generate the corresponding bytecodes. This is done by focusing on the core JavaScript constructs that the bytecode operations represent.

**8. Addressing the Register Optimizer (Advanced):**

The `register_optimizer_` is a more advanced concept. It's an optimization technique to reduce unnecessary register movements. The explanation should mention its purpose and how it interacts with the core bytecode generation process.

**9. Review and Refine:**

Finally, review the explanation for clarity, accuracy, and completeness. Ensure the JavaScript examples are correct and illustrate the point effectively. Use clear and concise language. For instance, instead of saying "this function manipulates registers," be more specific like "this function loads a value into a register."

This systematic approach, starting with high-level identification and gradually drilling down to specifics while maintaining the connection to JavaScript, allows for a comprehensive and accurate understanding of the code's functionality.
这个C++源代码文件 `bytecode-array-builder.cc` 是 V8 JavaScript 引擎中 **Ignition 解释器** 的一个核心组件，其主要功能是 **构建 JavaScript 代码的字节码表示形式 (Bytecode Array)**。

简单来说，它就像一个“字节码组装器”，将高级的 JavaScript 语法结构翻译成一系列可以在 V8 的解释器中执行的低级指令（即字节码）。

**核心功能归纳:**

1. **生成字节码指令:**  `BytecodeArrayBuilder` 提供了各种 `Output...` 和 `Create...Node` 方法，对应着不同的字节码指令。例如，`OutputLdar` (Load Accumulator Register) 将一个寄存器的值加载到累加器中，`OutputAdd` 执行加法运算。

2. **管理寄存器:**  它负责分配和管理在字节码执行过程中使用的虚拟寄存器。通过 `Register` 类来表示寄存器，并提供了如 `Parameter()`, `Local()` 等方法来获取特定用途的寄存器。

3. **处理控制流:**  它支持生成控制流相关的字节码，例如 `Jump` (跳转), `JumpIfTrue` (条件跳转), 以及循环结构 (`JumpLoop`)。它使用 `BytecodeLabel` 来标记代码位置，实现跳转目标。

4. **处理常量:**  它使用 `ConstantArrayBuilder` 来管理 JavaScript 代码中使用的常量（例如，字符串、数字、函数）。当需要使用常量时，`BytecodeArrayBuilder` 会将常量添加到常量池，并在字节码中引用其索引。

5. **处理作用域和上下文:**  它负责生成与作用域和上下文相关的字节码，例如创建闭包 (`CreateClosure`), 创建块级作用域 (`CreateBlockContext`), 以及访问上下文变量 (`LoadContextSlot`, `StoreContextSlot`).

6. **处理对象和属性访问:**  它支持生成用于对象创建 (`CreateObjectLiteral`), 属性访问 (`LoadNamedProperty`, `SetKeyedProperty`), 函数调用 (`CallProperty`), 以及构造函数调用 (`Construct`) 的字节码。

7. **支持 try-catch 异常处理:**  通过 `MarkTryBegin`, `MarkTryEnd`, `MarkHandler` 等方法，可以标记 try-catch 语句的范围，并生成相应的字节码来处理异常。

8. **生成调试相关的字节码:**  例如 `Debugger()` 方法会生成一个触发调试器的字节码。

9. **优化 (可选):**  代码中包含 `BytecodeRegisterOptimizer`，表明 `BytecodeArrayBuilder` 可以与一个寄存器优化器协同工作，以减少不必要的寄存器移动，提高执行效率。

10. **最终生成 BytecodeArray:**  通过 `ToBytecodeArray()` 方法，可以将构建好的字节码指令序列、常量池等信息封装成一个 `BytecodeArray` 对象，供 Ignition 解释器执行。

**与 JavaScript 功能的关系及示例:**

`BytecodeArrayBuilder` 的工作是将 JavaScript 代码翻译成可以执行的指令。几乎所有的 JavaScript 语法和特性都会在 `BytecodeArrayBuilder` 中找到对应的字节码生成逻辑。

**JavaScript 示例及对应的 (可能的) 字节码生成:**

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 10);
console.log(result);
```

**对应的 (可能的) 字节码生成过程 (简化说明):**

1. **`function add(a, b)`:**
   - `BytecodeArrayBuilder` 会创建一个 `BytecodeArray` 用于 `add` 函数。
   - 它会分配寄存器给参数 `a` 和 `b`。
   - 可能会生成 `CreateClosure` 字节码来创建函数对象。

2. **`return a + b;`:**
   - `BytecodeArrayBuilder` 会生成 `Ldar` 指令将 `a` 的值加载到累加器。
   - 然后生成 `Add` 指令，将 `b` 的值与累加器中的值相加。
   - 最后生成 `Return` 指令返回累加器中的结果。

3. **`let result = add(5, 10);`:**
   - `BytecodeArrayBuilder` 会将常量 `5` 和 `10` 添加到常量池，并生成 `LdaConstant` 指令将它们加载到寄存器中。
   - 生成 `CallProperty` (或类似的指令) 调用 `add` 函数，并将参数寄存器传递给它。
   - 生成 `Star` 指令将 `add` 函数的返回值存储到 `result` 对应的寄存器中。

4. **`console.log(result);`:**
   - `BytecodeArrayBuilder` 会查找 `console.log` 的位置（可能是全局对象或上下文）。
   - 生成 `Ldar` 指令将 `result` 的值加载到寄存器。
   - 生成 `CallProperty` (或类似的指令) 调用 `console.log`，并将 `result` 的值作为参数传递。

**更具体的 JavaScript 示例和可能的字节码映射:**

| JavaScript 代码片段        | 可能生成的字节码 (简化)      | `BytecodeArrayBuilder` 相关方法                     |
|-----------------------------|------------------------------|----------------------------------------------------|
| `let x = 10;`              | `LdaSmi 10`, `Star r0`       | `OutputLdaSmi`, `OutputStar`                        |
| `if (condition) { ... }`   | `JumpIfFalse label`, `...`, `Bind label` | `OutputJumpIfFalse`, `Bind`                         |
| `for (let i = 0; ...)`     | `LdaZero`, `Star r1`, `Bind loop_start`, `...`, `JumpLoop loop_start` | `OutputLdaZero`, `OutputStar`, `Bind`, `OutputJumpLoop` |
| `obj.property`           | `Ldar obj_reg`, `GetNamedProperty obj_reg, "property"` | `OutputLdar`, `OutputGetNamedProperty`               |
| `obj.method(arg)`        | `Ldar obj_reg`, `Ldar arg_reg`, `CallProperty obj_reg, arg_reg` | `OutputLdar`, `OutputCallProperty`                  |
| `function foo() { ... }` | `CreateClosure`, `Star foo_reg` | `OutputCreateClosure`, `OutputStar`                |
| `try { ... } catch (e) { ... }` | `MarkTryBegin handler_id`, `...`, `MarkHandler handler_id` | `MarkTryBegin`, `MarkHandler`                        |

**总结:**

`bytecode-array-builder.cc` 文件中的 `BytecodeArrayBuilder` 类是 V8 引擎中至关重要的一个组件，它负责将 JavaScript 代码转换成可以直接在解释器中执行的字节码。理解它的功能有助于深入理解 JavaScript 代码的执行过程以及 V8 引擎的内部工作机制。它通过一系列方法来生成和组织字节码指令，管理寄存器和常量，并处理各种 JavaScript 语言结构，最终生成可执行的 `BytecodeArray`。

Prompt: 
```
这是目录为v8/src/interpreter/bytecode-array-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/interpreter/bytecode-array-builder.h"

#include <optional>

#include "src/ast/scopes.h"
#include "src/ast/variables.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/interpreter/bytecode-array-writer.h"
#include "src/interpreter/bytecode-jump-table.h"
#include "src/interpreter/bytecode-label.h"
#include "src/interpreter/bytecode-node.h"
#include "src/interpreter/bytecode-register-optimizer.h"
#include "src/interpreter/bytecode-source-info.h"
#include "src/interpreter/interpreter-intrinsics.h"
#include "src/objects/feedback-vector-inl.h"
#include "src/objects/smi.h"

namespace v8 {
namespace internal {
namespace interpreter {

class RegisterTransferWriter final
    : public NON_EXPORTED_BASE(BytecodeRegisterOptimizer::BytecodeWriter),
      public NON_EXPORTED_BASE(ZoneObject) {
 public:
  explicit RegisterTransferWriter(BytecodeArrayBuilder* builder)
      : builder_(builder) {}
  ~RegisterTransferWriter() override = default;

  void EmitLdar(Register input) override { builder_->OutputLdarRaw(input); }

  void EmitStar(Register output) override { builder_->OutputStarRaw(output); }

  void EmitMov(Register input, Register output) override {
    builder_->OutputMovRaw(input, output);
  }

 private:
  BytecodeArrayBuilder* builder_;
};

BytecodeArrayBuilder::BytecodeArrayBuilder(
    Zone* zone, int parameter_count, int locals_count,
    FeedbackVectorSpec* feedback_vector_spec,
    SourcePositionTableBuilder::RecordingMode source_position_mode)
    : zone_(zone),
      feedback_vector_spec_(feedback_vector_spec),
      bytecode_generated_(false),
      constant_array_builder_(zone),
      handler_table_builder_(zone),
      parameter_count_(parameter_count),
      max_arguments_(0),
      local_register_count_(locals_count),
      register_allocator_(fixed_register_count()),
      bytecode_array_writer_(zone, &constant_array_builder_,
                             source_position_mode),
      register_optimizer_(nullptr) {
  DCHECK_GE(parameter_count_, 0);
  DCHECK_LE(parameter_count_, std::numeric_limits<uint16_t>::max());
  DCHECK_GE(local_register_count_, 0);

  if (v8_flags.ignition_reo) {
    register_optimizer_ = zone->New<BytecodeRegisterOptimizer>(
        zone, &register_allocator_, fixed_register_count(), parameter_count,
        zone->New<RegisterTransferWriter>(this));
  }
}

Register BytecodeArrayBuilder::Parameter(int parameter_index) const {
  DCHECK_GE(parameter_index, 0);
  // The parameter indices are shifted by 1 (receiver is the
  // first entry).
  return Register::FromParameterIndex(parameter_index + 1);
}

Register BytecodeArrayBuilder::Receiver() const {
  return Register::FromParameterIndex(0);
}

Register BytecodeArrayBuilder::Local(int index) const {
  DCHECK_LT(index, locals_count());
  return Register(index);
}

template <typename IsolateT>
Handle<BytecodeArray> BytecodeArrayBuilder::ToBytecodeArray(IsolateT* isolate) {
  DCHECK(RemainderOfBlockIsDead());
  DCHECK(!bytecode_generated_);
  bytecode_generated_ = true;

  int register_count = total_register_count();

  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_count = register_optimizer_->maxiumum_register_index() + 1;
  }

  Handle<TrustedByteArray> handler_table =
      handler_table_builder()->ToHandlerTable(isolate);
  return bytecode_array_writer_.ToBytecodeArray(isolate, register_count,
                                                parameter_count(),
                                                max_arguments(), handler_table);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<BytecodeArray> BytecodeArrayBuilder::ToBytecodeArray(
        Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<BytecodeArray> BytecodeArrayBuilder::ToBytecodeArray(
        LocalIsolate* isolate);

#ifdef DEBUG
int BytecodeArrayBuilder::CheckBytecodeMatches(Tagged<BytecodeArray> bytecode) {
  DisallowGarbageCollection no_gc;
  return bytecode_array_writer_.CheckBytecodeMatches(bytecode);
}
#endif

template <typename IsolateT>
Handle<TrustedByteArray> BytecodeArrayBuilder::ToSourcePositionTable(
    IsolateT* isolate) {
  DCHECK(RemainderOfBlockIsDead());

  return bytecode_array_writer_.ToSourcePositionTable(isolate);
}

template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> BytecodeArrayBuilder::ToSourcePositionTable(
        Isolate* isolate);
template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    Handle<TrustedByteArray> BytecodeArrayBuilder::ToSourcePositionTable(
        LocalIsolate* isolate);

BytecodeSourceInfo BytecodeArrayBuilder::CurrentSourcePosition(
    Bytecode bytecode) {
  BytecodeSourceInfo source_position;
  if (latest_source_info_.is_valid()) {
    // Statement positions need to be emitted immediately.  Expression
    // positions can be pushed back until a bytecode is found that can
    // throw (if expression position filtering is turned on). We only
    // invalidate the existing source position information if it is used.
    if (latest_source_info_.is_statement() ||
        !v8_flags.ignition_filter_expression_positions ||
        !Bytecodes::IsWithoutExternalSideEffects(bytecode)) {
      source_position = latest_source_info_;
      latest_source_info_.set_invalid();
    }
  }
  return source_position;
}

void BytecodeArrayBuilder::SetDeferredSourceInfo(
    BytecodeSourceInfo source_info) {
  if (!source_info.is_valid()) return;
  deferred_source_info_ = source_info;
}

void BytecodeArrayBuilder::AttachOrEmitDeferredSourceInfo(BytecodeNode* node) {
  if (!deferred_source_info_.is_valid()) return;
  if (!node->source_info().is_valid()) {
    node->set_source_info(deferred_source_info_);
  } else if (deferred_source_info_.is_statement() &&
             node->source_info().is_expression()) {
    BytecodeSourceInfo source_position = node->source_info();
    source_position.MakeStatementPosition(source_position.source_position());
    node->set_source_info(source_position);
  }
  deferred_source_info_.set_invalid();
}

void BytecodeArrayBuilder::Write(BytecodeNode* node) {
  AttachOrEmitDeferredSourceInfo(node);
  bytecode_array_writer_.Write(node);
}

void BytecodeArrayBuilder::WriteJump(BytecodeNode* node, BytecodeLabel* label) {
  AttachOrEmitDeferredSourceInfo(node);
  bytecode_array_writer_.WriteJump(node, label);
}

void BytecodeArrayBuilder::WriteJumpLoop(BytecodeNode* node,
                                         BytecodeLoopHeader* loop_header) {
  AttachOrEmitDeferredSourceInfo(node);
  bytecode_array_writer_.WriteJumpLoop(node, loop_header);
}

void BytecodeArrayBuilder::WriteSwitch(BytecodeNode* node,
                                       BytecodeJumpTable* jump_table) {
  AttachOrEmitDeferredSourceInfo(node);
  bytecode_array_writer_.WriteSwitch(node, jump_table);
}

void BytecodeArrayBuilder::OutputLdarRaw(Register reg) {
  uint32_t operand = static_cast<uint32_t>(reg.ToOperand());
  BytecodeNode node(BytecodeNode::Ldar(BytecodeSourceInfo(), operand));
  Write(&node);
}

void BytecodeArrayBuilder::OutputStarRaw(Register reg) {
  uint32_t operand = static_cast<uint32_t>(reg.ToOperand());
  std::optional<Bytecode> short_code = reg.TryToShortStar();
  BytecodeNode node = short_code
                          ? BytecodeNode(*short_code)
                          : BytecodeNode::Star(BytecodeSourceInfo(), operand);
  Write(&node);
}

void BytecodeArrayBuilder::OutputMovRaw(Register src, Register dest) {
  uint32_t operand0 = static_cast<uint32_t>(src.ToOperand());
  uint32_t operand1 = static_cast<uint32_t>(dest.ToOperand());
  BytecodeNode node(
      BytecodeNode::Mov(BytecodeSourceInfo(), operand0, operand1));
  Write(&node);
}

namespace {

template <OperandTypeInfo type_info>
class UnsignedOperandHelper {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    size_t value) {
    DCHECK(IsValid(value));
    return static_cast<uint32_t>(value);
  }

  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder, int value) {
    DCHECK_GE(value, 0);
    return Convert(builder, static_cast<size_t>(value));
  }

 private:
  static bool IsValid(size_t value) {
    switch (type_info) {
      case OperandTypeInfo::kFixedUnsignedByte:
        return value <= kMaxUInt8;
      case OperandTypeInfo::kFixedUnsignedShort:
        return value <= kMaxUInt16;
      case OperandTypeInfo::kScalableUnsignedByte:
        return value <= kMaxUInt32;
      default:
        UNREACHABLE();
    }
  }
};

template <OperandType>
class OperandHelper {};

#define DEFINE_UNSIGNED_OPERAND_HELPER(Name, Type) \
  template <>                                      \
  class OperandHelper<OperandType::k##Name>        \
      : public UnsignedOperandHelper<Type> {};
UNSIGNED_FIXED_SCALAR_OPERAND_TYPE_LIST(DEFINE_UNSIGNED_OPERAND_HELPER)
UNSIGNED_SCALABLE_SCALAR_OPERAND_TYPE_LIST(DEFINE_UNSIGNED_OPERAND_HELPER)
#undef DEFINE_UNSIGNED_OPERAND_HELPER

template <>
class OperandHelper<OperandType::kImm> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder, int value) {
    return static_cast<uint32_t>(value);
  }
};

template <>
class OperandHelper<OperandType::kReg> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    Register reg) {
    return builder->GetInputRegisterOperand(reg);
  }
};

template <>
class OperandHelper<OperandType::kRegList> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    RegisterList reg_list) {
    return builder->GetInputRegisterListOperand(reg_list);
  }
};

template <>
class OperandHelper<OperandType::kRegPair> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    RegisterList reg_list) {
    DCHECK_EQ(reg_list.register_count(), 2);
    return builder->GetInputRegisterListOperand(reg_list);
  }
};

template <>
class OperandHelper<OperandType::kRegOut> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    Register reg) {
    return builder->GetOutputRegisterOperand(reg);
  }
};

template <>
class OperandHelper<OperandType::kRegOutList> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    RegisterList reg_list) {
    return builder->GetOutputRegisterListOperand(reg_list);
  }
};

template <>
class OperandHelper<OperandType::kRegOutPair> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    RegisterList reg_list) {
    DCHECK_EQ(2, reg_list.register_count());
    return builder->GetOutputRegisterListOperand(reg_list);
  }
};

template <>
class OperandHelper<OperandType::kRegOutTriple> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    RegisterList reg_list) {
    DCHECK_EQ(3, reg_list.register_count());
    return builder->GetOutputRegisterListOperand(reg_list);
  }
};

template <>
class OperandHelper<OperandType::kRegInOut> {
 public:
  V8_INLINE static uint32_t Convert(BytecodeArrayBuilder* builder,
                                    Register reg) {
    return builder->GetInputOutputRegisterOperand(reg);
  }
};

}  // namespace

template <Bytecode bytecode, ImplicitRegisterUse implicit_register_use,
          OperandType... operand_types>
class BytecodeNodeBuilder {
 public:
  template <typename... Operands>
  V8_INLINE static BytecodeNode Make(BytecodeArrayBuilder* builder,
                                     Operands... operands) {
    static_assert(sizeof...(Operands) <= Bytecodes::kMaxOperands,
                  "too many operands for bytecode");
    builder->PrepareToOutputBytecode<bytecode, implicit_register_use>();
    // The "OperandHelper<operand_types>::Convert(builder, operands)..." will
    // expand both the OperandType... and Operands... parameter packs e.g. for:
    //   BytecodeNodeBuilder<OperandType::kReg, OperandType::kImm>::Make<
    //       Register, int>(..., Register reg, int immediate)
    // the code will expand into:
    //    OperandHelper<OperandType::kReg>::Convert(builder, reg),
    //    OperandHelper<OperandType::kImm>::Convert(builder, immediate),
    return BytecodeNode::Create<bytecode, implicit_register_use,
                                operand_types...>(
        builder->CurrentSourcePosition(bytecode),
        OperandHelper<operand_types>::Convert(builder, operands)...);
  }
};

#define DEFINE_BYTECODE_OUTPUT(name, ...)                             \
  template <typename... Operands>                                     \
  BytecodeNode BytecodeArrayBuilder::Create##name##Node(              \
      Operands... operands) {                                         \
    return BytecodeNodeBuilder<Bytecode::k##name, __VA_ARGS__>::Make( \
        this, operands...);                                           \
  }                                                                   \
                                                                      \
  template <typename... Operands>                                     \
  void BytecodeArrayBuilder::Output##name(Operands... operands) {     \
    BytecodeNode node(Create##name##Node(operands...));               \
    Write(&node);                                                     \
  }                                                                   \
                                                                      \
  template <typename... Operands>                                     \
  void BytecodeArrayBuilder::Output##name(BytecodeLabel* label,       \
                                          Operands... operands) {     \
    DCHECK(Bytecodes::IsForwardJump(Bytecode::k##name));              \
    BytecodeNode node(Create##name##Node(operands...));               \
    WriteJump(&node, label);                                          \
  }
BYTECODE_LIST(DEFINE_BYTECODE_OUTPUT, DEFINE_BYTECODE_OUTPUT)
#undef DEFINE_BYTECODE_OUTPUT

void BytecodeArrayBuilder::OutputJumpLoop(BytecodeLoopHeader* loop_header,
                                          int loop_depth, int feedback_slot) {
  BytecodeNode node(CreateJumpLoopNode(0, loop_depth, feedback_slot));
  WriteJumpLoop(&node, loop_header);
}

void BytecodeArrayBuilder::OutputSwitchOnSmiNoFeedback(
    BytecodeJumpTable* jump_table) {
  BytecodeNode node(CreateSwitchOnSmiNoFeedbackNode(
      jump_table->constant_pool_index(), jump_table->size(),
      jump_table->case_value_base()));
  WriteSwitch(&node, jump_table);
}

BytecodeArrayBuilder& BytecodeArrayBuilder::BinaryOperation(Token::Value op,
                                                            Register reg,
                                                            int feedback_slot) {
  switch (op) {
    case Token::kAdd:
      OutputAdd(reg, feedback_slot);
      break;
    case Token::kSub:
      OutputSub(reg, feedback_slot);
      break;
    case Token::kMul:
      OutputMul(reg, feedback_slot);
      break;
    case Token::kDiv:
      OutputDiv(reg, feedback_slot);
      break;
    case Token::kMod:
      OutputMod(reg, feedback_slot);
      break;
    case Token::kExp:
      OutputExp(reg, feedback_slot);
      break;
    case Token::kBitOr:
      OutputBitwiseOr(reg, feedback_slot);
      break;
    case Token::kBitXor:
      OutputBitwiseXor(reg, feedback_slot);
      break;
    case Token::kBitAnd:
      OutputBitwiseAnd(reg, feedback_slot);
      break;
    case Token::kShl:
      OutputShiftLeft(reg, feedback_slot);
      break;
    case Token::kSar:
      OutputShiftRight(reg, feedback_slot);
      break;
    case Token::kShr:
      OutputShiftRightLogical(reg, feedback_slot);
      break;
    default:
      UNREACHABLE();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::BinaryOperationSmiLiteral(
    Token::Value op, Tagged<Smi> literal, int feedback_slot) {
  switch (op) {
    case Token::kAdd:
      OutputAddSmi(literal.value(), feedback_slot);
      break;
    case Token::kSub:
      OutputSubSmi(literal.value(), feedback_slot);
      break;
    case Token::kMul:
      OutputMulSmi(literal.value(), feedback_slot);
      break;
    case Token::kDiv:
      OutputDivSmi(literal.value(), feedback_slot);
      break;
    case Token::kMod:
      OutputModSmi(literal.value(), feedback_slot);
      break;
    case Token::kExp:
      OutputExpSmi(literal.value(), feedback_slot);
      break;
    case Token::kBitOr:
      OutputBitwiseOrSmi(literal.value(), feedback_slot);
      break;
    case Token::kBitXor:
      OutputBitwiseXorSmi(literal.value(), feedback_slot);
      break;
    case Token::kBitAnd:
      OutputBitwiseAndSmi(literal.value(), feedback_slot);
      break;
    case Token::kShl:
      OutputShiftLeftSmi(literal.value(), feedback_slot);
      break;
    case Token::kSar:
      OutputShiftRightSmi(literal.value(), feedback_slot);
      break;
    case Token::kShr:
      OutputShiftRightLogicalSmi(literal.value(), feedback_slot);
      break;
    default:
      UNREACHABLE();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::UnaryOperation(Token::Value op,
                                                           int feedback_slot) {
  switch (op) {
    case Token::kInc:
      OutputInc(feedback_slot);
      break;
    case Token::kDec:
      OutputDec(feedback_slot);
      break;
    case Token::kAdd:
      OutputToNumber(feedback_slot);
      break;
    case Token::kSub:
      OutputNegate(feedback_slot);
      break;
    case Token::kBitNot:
      OutputBitwiseNot(feedback_slot);
      break;
    default:
      UNREACHABLE();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LogicalNot(ToBooleanMode mode) {
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    OutputLogicalNot();
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputToBooleanLogicalNot();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::TypeOf(int feedback_slot) {
  OutputTypeOf(feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::GetSuperConstructor(Register out) {
  OutputGetSuperConstructor(out);
  return *this;
}

BytecodeArrayBuilder&
BytecodeArrayBuilder::FindNonDefaultConstructorOrConstruct(
    Register this_function, Register new_target, RegisterList output) {
  OutputFindNonDefaultConstructorOrConstruct(this_function, new_target, output);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareOperation(
    Token::Value op, Register reg, int feedback_slot) {
  switch (op) {
    case Token::kEq:
      OutputTestEqual(reg, feedback_slot);
      break;
    case Token::kEqStrict:
      OutputTestEqualStrict(reg, feedback_slot);
      break;
    case Token::kLessThan:
      OutputTestLessThan(reg, feedback_slot);
      break;
    case Token::kGreaterThan:
      OutputTestGreaterThan(reg, feedback_slot);
      break;
    case Token::kLessThanEq:
      OutputTestLessThanOrEqual(reg, feedback_slot);
      break;
    case Token::kGreaterThanEq:
      OutputTestGreaterThanOrEqual(reg, feedback_slot);
      break;
    case Token::kInstanceOf:
      OutputTestInstanceOf(reg, feedback_slot);
      break;
    case Token::kIn:
      OutputTestIn(reg, feedback_slot);
      break;
    default:
      UNREACHABLE();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareReference(Register reg) {
  OutputTestReferenceEqual(reg);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareUndetectable() {
  OutputTestUndetectable();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareUndefined() {
  OutputTestUndefined();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareNull() {
  OutputTestNull();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareNil(Token::Value op,
                                                       NilValue nil) {
  if (op == Token::kEq) {
    return CompareUndetectable();
  } else {
    DCHECK_EQ(Token::kEqStrict, op);
    if (nil == kUndefinedValue) {
      return CompareUndefined();
    } else {
      DCHECK_EQ(kNullValue, nil);
      return CompareNull();
    }
  }
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CompareTypeOf(
    TestTypeOfFlags::LiteralFlag literal_flag) {
  DCHECK_NE(literal_flag, TestTypeOfFlags::LiteralFlag::kOther);
  OutputTestTypeOf(TestTypeOfFlags::Encode(literal_flag));
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadConstantPoolEntry(
    size_t entry) {
  OutputLdaConstant(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLiteral(Tagged<Smi> smi) {
  int32_t raw_smi = smi.value();
  if (raw_smi == 0) {
    OutputLdaZero();
  } else {
    OutputLdaSmi(raw_smi);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLiteral(double value) {
  // If we can encode the value as a Smi, we should.
  int smi;
  if (DoubleToSmiInteger(value, &smi)) {
    LoadLiteral(Smi::FromInt(smi));
  } else {
    size_t entry = GetConstantPoolEntry(value);
    OutputLdaConstant(entry);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLiteral(
    const AstRawString* raw_string) {
  size_t entry = GetConstantPoolEntry(raw_string);
  OutputLdaConstant(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLiteral(
    const AstConsString* cons_string) {
  size_t entry = GetConstantPoolEntry(cons_string);
  OutputLdaConstant(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLiteral(const Scope* scope) {
  size_t entry = GetConstantPoolEntry(scope);
  OutputLdaConstant(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLiteral(AstBigInt bigint) {
  size_t entry = GetConstantPoolEntry(bigint);
  OutputLdaConstant(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadUndefined() {
  OutputLdaUndefined();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadNull() {
  OutputLdaNull();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadTheHole() {
  OutputLdaTheHole();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadTrue() {
  OutputLdaTrue();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadFalse() {
  OutputLdaFalse();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadBoolean(bool value) {
  return value ? LoadTrue() : LoadFalse();
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadAccumulatorWithRegister(
    Register reg) {
  if (register_optimizer_) {
    // Defer source info so that if we elide the bytecode transfer, we attach
    // the source info to a subsequent bytecode if it exists.
    SetDeferredSourceInfo(CurrentSourcePosition(Bytecode::kLdar));
    register_optimizer_->DoLdar(reg);
  } else {
    OutputLdar(reg);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreAccumulatorInRegister(
    Register reg) {
  if (register_optimizer_) {
    // Defer source info so that if we elide the bytecode transfer, we attach
    // the source info to a subsequent bytecode if it exists.
    SetDeferredSourceInfo(CurrentSourcePosition(Bytecode::kStar));
    register_optimizer_->DoStar(reg);
  } else {
    OutputStarRaw(reg);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MoveRegister(Register from,
                                                         Register to) {
  DCHECK(from != to);
  if (register_optimizer_) {
    // Defer source info so that if we elide the bytecode transfer, we attach
    // the source info to a subsequent bytecode if it exists.
    SetDeferredSourceInfo(CurrentSourcePosition(Bytecode::kMov));
    register_optimizer_->DoMov(from, to);
  } else {
    OutputMov(from, to);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadGlobal(const AstRawString* name,
                                                       int feedback_slot,
                                                       TypeofMode typeof_mode) {
  size_t name_index = GetConstantPoolEntry(name);
  // Ensure that typeof mode is in sync with the IC slot kind.
  DCHECK_EQ(GetTypeofModeFromSlotKind(feedback_vector_spec()->GetKind(
                FeedbackVector::ToSlot(feedback_slot))),
            typeof_mode);
  switch (typeof_mode) {
    case TypeofMode::kInside:
      OutputLdaGlobalInsideTypeof(name_index, feedback_slot);
      break;
    case TypeofMode::kNotInside:
      OutputLdaGlobal(name_index, feedback_slot);
      break;
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreGlobal(
    const AstRawString* name, int feedback_slot) {
  size_t name_index = GetConstantPoolEntry(name);
  OutputStaGlobal(name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadContextSlot(
    Register context, Variable* variable, int depth,
    ContextSlotMutability mutability) {
  int slot_index = variable->index();
  if (mutability == kImmutableSlot) {
    if (context.is_current_context() && depth == 0) {
      OutputLdaImmutableCurrentContextSlot(slot_index);
    } else {
      OutputLdaImmutableContextSlot(context, slot_index, depth);
    }
  } else {
    DCHECK_EQ(kMutableSlot, mutability);
    if (v8_flags.script_context_mutable_heap_number &&
        variable->scope()->is_script_scope()) {
      if (context.is_current_context() && depth == 0) {
        OutputLdaCurrentScriptContextSlot(slot_index);
      } else {
        OutputLdaScriptContextSlot(context, slot_index, depth);
      }
    } else {
      if (context.is_current_context() && depth == 0) {
        OutputLdaCurrentContextSlot(slot_index);
      } else {
        OutputLdaContextSlot(context, slot_index, depth);
      }
    }
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreContextSlot(Register context,
                                                             Variable* variable,
                                                             int depth) {
  int slot_index = variable->index();
  if ((v8_flags.script_context_mutable_heap_number ||
       (v8_flags.const_tracking_let &&
        variable->mode() == VariableMode::kLet)) &&
      variable->scope()->is_script_scope()) {
    if (context.is_current_context() && depth == 0) {
      OutputStaCurrentScriptContextSlot(slot_index);
    } else {
      OutputStaScriptContextSlot(context, slot_index, depth);
    }
  } else {
    if (context.is_current_context() && depth == 0) {
      OutputStaCurrentContextSlot(slot_index);
    } else {
      OutputStaContextSlot(context, slot_index, depth);
    }
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLookupSlot(
    const AstRawString* name, TypeofMode typeof_mode) {
  size_t name_index = GetConstantPoolEntry(name);
  switch (typeof_mode) {
    case TypeofMode::kInside:
      OutputLdaLookupSlotInsideTypeof(name_index);
      break;
    case TypeofMode::kNotInside:
      OutputLdaLookupSlot(name_index);
      break;
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLookupContextSlot(
    const AstRawString* name, TypeofMode typeof_mode, ContextKind context_kind,
    int slot_index, int depth) {
  size_t name_index = GetConstantPoolEntry(name);
  switch (typeof_mode) {
    case TypeofMode::kInside:
      if (v8_flags.script_context_mutable_heap_number &&
          context_kind == ContextKind::kScriptContext) {
        OutputLdaLookupScriptContextSlotInsideTypeof(name_index, slot_index,
                                                     depth);
      } else {
        OutputLdaLookupContextSlotInsideTypeof(name_index, slot_index, depth);
      }
      break;
    case TypeofMode::kNotInside:
      if (v8_flags.script_context_mutable_heap_number &&
          context_kind == ContextKind::kScriptContext) {
        OutputLdaLookupScriptContextSlot(name_index, slot_index, depth);
      } else {
        OutputLdaLookupContextSlot(name_index, slot_index, depth);
      }
      break;
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadLookupGlobalSlot(
    const AstRawString* name, TypeofMode typeof_mode, int feedback_slot,
    int depth) {
  size_t name_index = GetConstantPoolEntry(name);
  switch (typeof_mode) {
    case TypeofMode::kInside:
      OutputLdaLookupGlobalSlotInsideTypeof(name_index, feedback_slot, depth);
      break;
    case TypeofMode::kNotInside:
      OutputLdaLookupGlobalSlot(name_index, feedback_slot, depth);
      break;
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreLookupSlot(
    const AstRawString* name, LanguageMode language_mode,
    LookupHoistingMode lookup_hoisting_mode) {
  size_t name_index = GetConstantPoolEntry(name);
  uint8_t flags =
      StoreLookupSlotFlags::Encode(language_mode, lookup_hoisting_mode);
  OutputStaLookupSlot(name_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadNamedProperty(
    Register object, const AstRawString* name, int feedback_slot) {
  size_t name_index = GetConstantPoolEntry(name);
  OutputGetNamedProperty(object, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadNamedPropertyFromSuper(
    Register object, const AstRawString* name, int feedback_slot) {
  size_t name_index = GetConstantPoolEntry(name);
  OutputGetNamedPropertyFromSuper(object, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadKeyedProperty(
    Register object, int feedback_slot) {
  OutputGetKeyedProperty(object, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadEnumeratedKeyedProperty(
    Register object, Register enum_index, Register cache_type,
    int feedback_slot) {
  OutputGetEnumeratedKeyedProperty(object, enum_index, cache_type,
                                   feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadIteratorProperty(
    Register object, int feedback_slot) {
  size_t name_index = IteratorSymbolConstantPoolEntry();
  OutputGetNamedProperty(object, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::GetIterator(
    Register object, int load_feedback_slot, int call_feedback_slot) {
  OutputGetIterator(object, load_feedback_slot, call_feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadAsyncIteratorProperty(
    Register object, int feedback_slot) {
  size_t name_index = AsyncIteratorSymbolConstantPoolEntry();
  OutputGetNamedProperty(object, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::DefineKeyedOwnPropertyInLiteral(
    Register object, Register name, DefineKeyedOwnPropertyInLiteralFlags flags,
    int feedback_slot) {
  OutputDefineKeyedOwnPropertyInLiteral(object, name, flags, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SetNamedProperty(
    Register object, size_t name_index, int feedback_slot,
    LanguageMode language_mode) {
  // Ensure that language mode is in sync with the IC slot kind.
  DCHECK_EQ(GetLanguageModeFromSlotKind(feedback_vector_spec()->GetKind(
                FeedbackVector::ToSlot(feedback_slot))),
            language_mode);
  OutputSetNamedProperty(object, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SetNamedProperty(
    Register object, const AstRawString* name, int feedback_slot,
    LanguageMode language_mode) {
  size_t name_index = GetConstantPoolEntry(name);
  return SetNamedProperty(object, name_index, feedback_slot, language_mode);
}

BytecodeArrayBuilder& BytecodeArrayBuilder::DefineNamedOwnProperty(
    Register object, const AstRawString* name, int feedback_slot) {
  size_t name_index = GetConstantPoolEntry(name);
  // Ensure that the store operation is in sync with the IC slot kind.
  DCHECK_EQ(
      FeedbackSlotKind::kDefineNamedOwn,
      feedback_vector_spec()->GetKind(FeedbackVector::ToSlot(feedback_slot)));
  OutputDefineNamedOwnProperty(object, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SetKeyedProperty(
    Register object, Register key, int feedback_slot,
    LanguageMode language_mode) {
  // Ensure that language mode is in sync with the IC slot kind.
  DCHECK_EQ(GetLanguageModeFromSlotKind(feedback_vector_spec()->GetKind(
                FeedbackVector::ToSlot(feedback_slot))),
            language_mode);
  OutputSetKeyedProperty(object, key, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::DefineKeyedOwnProperty(
    Register object, Register key, DefineKeyedOwnPropertyFlags flags,
    int feedback_slot) {
  // Ensure that the IC uses a strict language mode, as this is the only
  // supported mode for this use case.
  DCHECK_EQ(GetLanguageModeFromSlotKind(feedback_vector_spec()->GetKind(
                FeedbackVector::ToSlot(feedback_slot))),
            LanguageMode::kStrict);
  OutputDefineKeyedOwnProperty(object, key, flags, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreInArrayLiteral(
    Register array, Register index, int feedback_slot) {
  OutputStaInArrayLiteral(array, index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreClassFieldsInitializer(
    Register constructor, int feedback_slot) {
  size_t name_index = ClassFieldsSymbolConstantPoolEntry();
  return SetNamedProperty(constructor, name_index, feedback_slot,
                          LanguageMode::kStrict);
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadClassFieldsInitializer(
    Register constructor, int feedback_slot) {
  size_t name_index = ClassFieldsSymbolConstantPoolEntry();
  OutputGetNamedProperty(constructor, name_index, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateClosure(
    size_t shared_function_info_entry, int slot, int flags) {
  OutputCreateClosure(shared_function_info_entry, slot, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateBlockContext(
    const Scope* scope) {
  size_t entry = GetConstantPoolEntry(scope);
  OutputCreateBlockContext(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateCatchContext(
    Register exception, const Scope* scope) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateCatchContext(exception, scope_index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateFunctionContext(
    const Scope* scope, int slots) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateFunctionContext(scope_index, slots);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateEvalContext(
    const Scope* scope, int slots) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateEvalContext(scope_index, slots);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateWithContext(
    Register object, const Scope* scope) {
  size_t scope_index = GetConstantPoolEntry(scope);
  OutputCreateWithContext(object, scope_index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateArguments(
    CreateArgumentsType type) {
  switch (type) {
    case CreateArgumentsType::kMappedArguments:
      OutputCreateMappedArguments();
      break;
    case CreateArgumentsType::kUnmappedArguments:
      OutputCreateUnmappedArguments();
      break;
    case CreateArgumentsType::kRestParameter:
      OutputCreateRestParameter();
      break;
    default:
      UNREACHABLE();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateRegExpLiteral(
    const AstRawString* pattern, int literal_index, int flags) {
  size_t pattern_entry = GetConstantPoolEntry(pattern);
  OutputCreateRegExpLiteral(pattern_entry, literal_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateEmptyArrayLiteral(
    int literal_index) {
  OutputCreateEmptyArrayLiteral(literal_index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateArrayLiteral(
    size_t constant_elements_entry, int literal_index, int flags) {
  OutputCreateArrayLiteral(constant_elements_entry, literal_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateArrayFromIterable() {
  OutputCreateArrayFromIterable();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateObjectLiteral(
    size_t constant_properties_entry, int literal_index, int flags) {
  OutputCreateObjectLiteral(constant_properties_entry, literal_index, flags);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CreateEmptyObjectLiteral() {
  OutputCreateEmptyObjectLiteral();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CloneObject(Register source,
                                                        int flags,
                                                        int feedback_slot) {
  OutputCloneObject(source, flags, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::GetTemplateObject(
    size_t template_object_description_entry, int feedback_slot) {
  OutputGetTemplateObject(template_object_description_entry, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::PushContext(Register context) {
  OutputPushContext(context);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::PopContext(Register context) {
  OutputPopContext(context);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToObject(Register out) {
  OutputToObject(out);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToName() {
  OutputToName();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToString() {
  OutputToString();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToBoolean(ToBooleanMode mode) {
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    // No-op, the accumulator is already a boolean and ToBoolean both reads and
    // writes the accumulator.
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputToBoolean();
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToNumber(int feedback_slot) {
  OutputToNumber(feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ToNumeric(int feedback_slot) {
  OutputToNumeric(feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Bind(BytecodeLabel* label) {
  // Don't generate code for a label which hasn't had a corresponding forward
  // jump generated already. For backwards jumps, use BindLoopHeader.
  if (!label->has_referrer_jump()) return *this;

  // Flush the register optimizer when binding a label to ensure all
  // expected registers are valid when jumping to this label.
  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindLabel(label);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Bind(
    BytecodeLoopHeader* loop_header) {
  // Flush the register optimizer when starting a loop to ensure all expected
  // registers are valid when jumping to the loop header.
  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindLoopHeader(loop_header);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Bind(BytecodeJumpTable* jump_table,
                                                 int case_value) {
  // Flush the register optimizer when binding a jump table entry to ensure
  // all expected registers are valid when jumping to this location.
  if (register_optimizer_) {
    register_optimizer_->Flush();
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindJumpTableEntry(jump_table, case_value);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MarkHandler(
    int handler_id, HandlerTable::CatchPrediction catch_prediction) {
  // The handler starts a new basic block, and any reasonable try block won't
  // let control fall through into it.
  DCHECK_IMPLIES(register_optimizer_,
                 register_optimizer_->EnsureAllRegistersAreFlushed());
  DCHECK_IMPLIES(register_optimizer_,
                 register_optimizer_->IsAccumulatorReset());
  bytecode_array_writer_.BindHandlerTarget(handler_table_builder(), handler_id);
  handler_table_builder()->SetPrediction(handler_id, catch_prediction);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MarkTryBegin(int handler_id,
                                                         Register context) {
  // Flush registers to make sure everything visible to the handler is
  // materialized.
  if (register_optimizer_) register_optimizer_->Flush();
  bytecode_array_writer_.BindTryRegionStart(handler_table_builder(),
                                            handler_id);
  handler_table_builder()->SetContextRegister(handler_id, context);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::MarkTryEnd(int handler_id) {
  if (register_optimizer_) {
    register_optimizer_->ResetTypeHintForAccumulator();
  }
  bytecode_array_writer_.BindTryRegionEnd(handler_table_builder(), handler_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Jump(BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJump(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfTrue(ToBooleanMode mode,
                                                       BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    OutputJumpIfTrue(label, 0);
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputJumpIfToBooleanTrue(label, 0);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfFalse(ToBooleanMode mode,
                                                        BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  if (mode == ToBooleanMode::kAlreadyBoolean) {
    OutputJumpIfFalse(label, 0);
  } else {
    DCHECK_EQ(mode, ToBooleanMode::kConvertToBoolean);
    OutputJumpIfToBooleanFalse(label, 0);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNull(BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfNull(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNotNull(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfNotNull(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfUndefined(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfUndefined(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfUndefinedOrNull(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfUndefinedOrNull(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNotUndefined(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfNotUndefined(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNil(BytecodeLabel* label,
                                                      Token::Value op,
                                                      NilValue nil) {
  if (op == Token::kEq) {
    // TODO(rmcilroy): Implement JumpIfUndetectable.
    return CompareUndetectable().JumpIfTrue(ToBooleanMode::kAlreadyBoolean,
                                            label);
  } else {
    DCHECK_EQ(Token::kEqStrict, op);
    if (nil == kUndefinedValue) {
      return JumpIfUndefined(label);
    } else {
      DCHECK_EQ(kNullValue, nil);
      return JumpIfNull(label);
    }
  }
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfNotNil(BytecodeLabel* label,
                                                         Token::Value op,
                                                         NilValue nil) {
  if (op == Token::kEq) {
    // TODO(rmcilroy): Implement JumpIfUndetectable.
    return CompareUndetectable().JumpIfFalse(ToBooleanMode::kAlreadyBoolean,
                                             label);
  } else {
    DCHECK_EQ(Token::kEqStrict, op);
    if (nil == kUndefinedValue) {
      return JumpIfNotUndefined(label);
    } else {
      DCHECK_EQ(kNullValue, nil);
      return JumpIfNotNull(label);
    }
  }
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfJSReceiver(
    BytecodeLabel* label) {
  DCHECK(!label->is_bound());
  OutputJumpIfJSReceiver(label, 0);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpIfForInDone(
    BytecodeLabel* label, Register index, Register cache_length) {
  DCHECK(!label->is_bound());
  OutputJumpIfForInDone(label, 0, index, cache_length);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::JumpLoop(
    BytecodeLoopHeader* loop_header, int loop_depth, int position,
    int feedback_slot) {
  if (position != kNoSourcePosition) {
    // We need to attach a non-breakable source position to JumpLoop for its
    // implicit stack check, so we simply add it as expression position. There
    // can be a prior statement position from constructs like:
    //
    //    do var x;  while (false);
    //
    // A Nop could be inserted for empty statements, but since no code
    // is associated with these positions, instead we force the jump loop's
    // expression position which eliminates the empty statement's position.
    latest_source_info_.ForceExpressionPosition(position);
  }
  OutputJumpLoop(loop_header, loop_depth, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SwitchOnSmiNoFeedback(
    BytecodeJumpTable* jump_table) {
  OutputSwitchOnSmiNoFeedback(jump_table);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SetPendingMessage() {
  OutputSetPendingMessage();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Throw() {
  OutputThrow();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ReThrow() {
  OutputReThrow();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Abort(AbortReason reason) {
  DCHECK_LT(reason, AbortReason::kLastErrorMessage);
  DCHECK_GE(reason, AbortReason::kNoReason);
  OutputAbort(static_cast<int>(reason));
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Return() {
  OutputReturn();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowReferenceErrorIfHole(
    const AstRawString* name) {
  size_t entry = GetConstantPoolEntry(name);
  OutputThrowReferenceErrorIfHole(entry);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowSuperNotCalledIfHole() {
  OutputThrowSuperNotCalledIfHole();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowSuperAlreadyCalledIfNotHole() {
  OutputThrowSuperAlreadyCalledIfNotHole();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ThrowIfNotSuperConstructor(
    Register constructor) {
  OutputThrowIfNotSuperConstructor(constructor);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Debugger() {
  OutputDebugger();
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::IncBlockCounter(
    int coverage_array_slot) {
  OutputIncBlockCounter(coverage_array_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInEnumerate(Register receiver) {
  OutputForInEnumerate(receiver);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInPrepare(
    RegisterList cache_info_triple, int feedback_slot) {
  DCHECK_EQ(3, cache_info_triple.register_count());
  OutputForInPrepare(cache_info_triple, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInNext(
    Register receiver, Register index, RegisterList cache_type_array_pair,
    int feedback_slot) {
  DCHECK_EQ(2, cache_type_array_pair.register_count());
  OutputForInNext(receiver, index, cache_type_array_pair, feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ForInStep(Register index) {
  OutputForInStep(index);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::StoreModuleVariable(int cell_index,
                                                                int depth) {
  OutputStaModuleVariable(cell_index, depth);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::LoadModuleVariable(int cell_index,
                                                               int depth) {
  OutputLdaModuleVariable(cell_index, depth);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SuspendGenerator(
    Register generator, RegisterList registers, int suspend_id) {
  OutputSuspendGenerator(generator, registers, registers.register_count(),
                         suspend_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::SwitchOnGeneratorState(
    Register generator, BytecodeJumpTable* jump_table) {
  DCHECK_EQ(jump_table->case_value_base(), 0);
  BytecodeNode node(CreateSwitchOnGeneratorStateNode(
      generator, jump_table->constant_pool_index(), jump_table->size()));
  WriteSwitch(&node, jump_table);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ResumeGenerator(
    Register generator, RegisterList registers) {
  OutputResumeGenerator(generator, registers, registers.register_count());
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallProperty(Register callable,
                                                         RegisterList args,
                                                         int feedback_slot) {
  if (args.register_count() == 1) {
    OutputCallProperty0(callable, args[0], feedback_slot);
  } else if (args.register_count() == 2) {
    OutputCallProperty1(callable, args[0], args[1], feedback_slot);
  } else if (args.register_count() == 3) {
    OutputCallProperty2(callable, args[0], args[1], args[2], feedback_slot);
  } else {
    OutputCallProperty(callable, args, args.register_count(), feedback_slot);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallUndefinedReceiver(
    Register callable, RegisterList args, int feedback_slot) {
  if (args.register_count() == 0) {
    OutputCallUndefinedReceiver0(callable, feedback_slot);
  } else if (args.register_count() == 1) {
    OutputCallUndefinedReceiver1(callable, args[0], feedback_slot);
  } else if (args.register_count() == 2) {
    OutputCallUndefinedReceiver2(callable, args[0], args[1], feedback_slot);
  } else {
    OutputCallUndefinedReceiver(callable, args, args.register_count(),
                                feedback_slot);
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallAnyReceiver(Register callable,
                                                            RegisterList args,
                                                            int feedback_slot) {
  OutputCallAnyReceiver(callable, args, args.register_count(), feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallWithSpread(Register callable,
                                                           RegisterList args,
                                                           int feedback_slot) {
  OutputCallWithSpread(callable, args, args.register_count(), feedback_slot);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Construct(Register constructor,
                                                      RegisterList args,
                                                      int feedback_slot_id) {
  OutputConstruct(constructor, args, args.register_count(), feedback_slot_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ConstructWithSpread(
    Register constructor, RegisterList args, int feedback_slot_id) {
  OutputConstructWithSpread(constructor, args, args.register_count(),
                            feedback_slot_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::ConstructForwardAllArgs(
    Register constructor, int feedback_slot_id) {
  OutputConstructForwardAllArgs(constructor, feedback_slot_id);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntime(
    Runtime::FunctionId function_id, RegisterList args) {
  DCHECK_EQ(1, Runtime::FunctionForId(function_id)->result_size);
  DCHECK_LE(Bytecodes::SizeForUnsignedOperand(function_id),
            OperandSize::kShort);
  if (IntrinsicsHelper::IsSupported(function_id)) {
    IntrinsicsHelper::IntrinsicId intrinsic_id =
        IntrinsicsHelper::FromRuntimeId(function_id);
    OutputInvokeIntrinsic(static_cast<int>(intrinsic_id), args,
                          args.register_count());
  } else {
    OutputCallRuntime(static_cast<int>(function_id), args,
                      args.register_count());
  }
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntime(
    Runtime::FunctionId function_id, Register arg) {
  return CallRuntime(function_id, RegisterList(arg));
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntime(
    Runtime::FunctionId function_id) {
  return CallRuntime(function_id, RegisterList());
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntimeForPair(
    Runtime::FunctionId function_id, RegisterList args,
    RegisterList return_pair) {
  DCHECK_EQ(2, Runtime::FunctionForId(function_id)->result_size);
  DCHECK_LE(Bytecodes::SizeForUnsignedOperand(function_id),
            OperandSize::kShort);
  DCHECK_EQ(2, return_pair.register_count());
  OutputCallRuntimeForPair(static_cast<uint16_t>(function_id), args,
                           args.register_count(), return_pair);
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallRuntimeForPair(
    Runtime::FunctionId function_id, Register arg, RegisterList return_pair) {
  return CallRuntimeForPair(function_id, RegisterList(arg), return_pair);
}

BytecodeArrayBuilder& BytecodeArrayBuilder::CallJSRuntime(int context_index,
                                                          RegisterList args) {
  OutputCallJSRuntime(context_index, args, args.register_count());
  return *this;
}

BytecodeArrayBuilder& BytecodeArrayBuilder::Delete(Register object,
                                                   LanguageMode language_mode) {
  if (language_mode == LanguageMode::kSloppy) {
    OutputDeletePropertySloppy(object);
  } else {
    DCHECK_EQ(language_mode, LanguageMode::kStrict);
    OutputDeletePropertyStrict(object);
  }
  return *this;
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(
    const AstRawString* raw_string) {
  return constant_array_builder()->Insert(raw_string);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(
    const AstConsString* cons_string) {
  return constant_array_builder()->Insert(cons_string);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(AstBigInt bigint) {
  return constant_array_builder()->Insert(bigint);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(const Scope* scope) {
  return constant_array_builder()->Insert(scope);
}

size_t BytecodeArrayBuilder::GetConstantPoolEntry(double number) {
  return constant_array_builder()->Insert(number);
}

#define ENTRY_GETTER(NAME, ...)                            \
  size_t BytecodeArrayBuilder::NAME##ConstantPoolEntry() { \
    return constant_array_builder()->Insert##NAME();       \
  }
SINGLETON_CONSTANT_ENTRY_TYPES(ENTRY_GETTER)
#undef ENTRY_GETTER

BytecodeJumpTable* BytecodeArrayBuilder::AllocateJumpTable(
    int size, int case_value_base) {
  DCHECK_GT(size, 0);

  size_t constant_pool_index = constant_array_builder()->InsertJumpTable(size);

  return zone()->New<BytecodeJumpTable>(constant_pool_index, size,
                                        case_value_base, zone());
}

size_t BytecodeArrayBuilder::AllocateDeferredConstantPoolEntry() {
  return constant_array_builder()->InsertDeferred();
}

void BytecodeArrayBuilder::SetDeferredConstantPoolEntry(size_t entry,
                                                        Handle<Object> object) {
  constant_array_builder()->SetDeferredAt(entry, object);
}

bool BytecodeArrayBuilder::RegisterIsValid(Register reg) const {
  if (!reg.is_valid()) {
    return false;
  }

  if (reg.is_current_context() || reg.is_function_closure()) {
    return true;
  } else if (reg.is_parameter()) {
    int parameter_index = reg.ToParameterIndex();
    return parameter_index >= 0 && parameter_index < parameter_count();
  } else if (reg.index() < fixed_register_count()) {
    return true;
  } else {
    return register_allocator()->RegisterIsLive(reg);
  }
}

bool BytecodeArrayBuilder::RegisterListIsValid(RegisterList reg_list) const {
  if (reg_list.register_count() == 0) {
    return reg_list.first_register() == Register(0);
  } else {
    int first_reg_index = reg_list.first_register().index();
    for (int i = 0; i < reg_list.register_count(); i++) {
      if (!RegisterIsValid(Register(first_reg_index + i))) {
        return false;
      }
    }
    return true;
  }
}

template <Bytecode bytecode, ImplicitRegisterUse implicit_register_use>
void BytecodeArrayBuilder::PrepareToOutputBytecode() {
  if (register_optimizer_) {
    register_optimizer_->PrepareForBytecode<bytecode, implicit_register_use>();
  }
}

uint32_t BytecodeArrayBuilder::GetInputRegisterOperand(Register reg) {
  DCHECK(RegisterIsValid(reg));
  if (register_optimizer_) reg = register_optimizer_->GetInputRegister(reg);
  return static_cast<uint32_t>(reg.ToOperand());
}

uint32_t BytecodeArrayBuilder::GetOutputRegisterOperand(Register reg) {
  DCHECK(RegisterIsValid(reg));
  if (register_optimizer_) register_optimizer_->PrepareOutputRegister(reg);
  return static_cast<uint32_t>(reg.ToOperand());
}

uint32_t BytecodeArrayBuilder::GetInputOutputRegisterOperand(Register reg) {
  DCHECK(RegisterIsValid(reg));
  if (register_optimizer_) {
    register_optimizer_->PrepareOutputRegister(reg);
    DCHECK_EQ(reg, register_optimizer_->GetInputRegister(reg));
  }
  return static_cast<uint32_t>(reg.ToOperand());
}

uint32_t BytecodeArrayBuilder::GetInputRegisterListOperand(
    RegisterList reg_list) {
  DCHECK(RegisterListIsValid(reg_list));
  if (register_optimizer_)
    reg_list = register_optimizer_->GetInputRegisterList(reg_list);
  return static_cast<uint32_t>(reg_list.first_register().ToOperand());
}

uint32_t BytecodeArrayBuilder::GetOutputRegisterListOperand(
    RegisterList reg_list) {
  DCHECK(RegisterListIsValid(reg_list));
  if (register_optimizer_)
    register_optimizer_->PrepareOutputRegisterList(reg_list);
  return static_cast<uint32_t>(reg_list.first_register().ToOperand());
}

void BytecodeArrayBuilder::EmitFunctionStartSourcePosition(int position) {
  bytecode_array_writer_.SetFunctionEntrySourcePosition(position);
  // Force an expression position to make sure we have one. If the next bytecode
  // overwrites it, it’s fine since it would mean we have a source position
  // anyway.
  latest_source_info_.ForceExpressionPosition(position);
}

std::ostream& operator<<(std::ostream& os,
                         const BytecodeArrayBuilder::ToBooleanMode& mode) {
  switch (mode) {
    case BytecodeArrayBuilder::ToBooleanMode::kAlreadyBoolean:
      return os << "AlreadyBoolean";
    case BytecodeArrayBuilder::ToBooleanMode::kConvertToBoolean:
      return os << "ConvertToBoolean";
  }
  UNREACHABLE();
}

}  // namespace interpreter
}  // namespace internal
}  // namespace v8

"""

```