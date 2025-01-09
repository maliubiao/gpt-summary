Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `interpreter-generator.cc`.

Here's a breakdown of the thought process to achieve that:

1. **Identify the file's purpose:** The file is named `interpreter-generator.cc` and located within the `v8/src/interpreter` directory. This strongly suggests it's responsible for generating code or handling the execution of bytecode within V8's interpreter.

2. **Scan for key terms and patterns:**  Look for recurring words, macros, and structural elements. The code uses the `IGNITION_HANDLER` macro extensively. This macro seems to define handlers for specific bytecode instructions. The names passed to this macro (like `LdaZero`, `LdaSmi`, `Star`, `GetNamedProperty`, etc.) appear to be bytecode names.

3. **Analyze the `IGNITION_HANDLER` macro:**  The macro defines a class with a `GenerateImpl` method. This method likely contains the logic for handling the corresponding bytecode.

4. **Examine individual handlers:**  Go through a few of the handlers to understand their actions.
    * `LdaZero`: Loads the literal `0` into the accumulator.
    * `LdaSmi`: Loads a small integer into the accumulator.
    * `Ldar`: Loads a value from a register into the accumulator.
    * `Star`: Stores the accumulator into a register.
    * `GetNamedProperty`:  This one is more complex and involves `LoadIC`, hinting at property access.
    * `SetNamedProperty`: Involves `StoreIC`, suggesting property assignment.

5. **Identify common operations:** Many handlers involve:
    * **Loading values:**  Loading constants, registers, context variables, global variables.
    * **Storing values:** Storing to registers, context variables, global variables.
    * **Accumulator:**  A central register (the "accumulator") is frequently used.
    * **Dispatch:** The `Dispatch()` call at the end of many handlers likely advances the interpreter to the next instruction.
    * **Bytecode operands:**  Handlers access operands of the bytecode instructions.
    * **Feedback Vector:**  Mention of "FeedBackVector" and "IC" (Inline Cache) points to optimization techniques.
    * **Context:** Handling of contexts suggests scope and variable resolution.
    * **Runtime calls:**  Calls to `CallRuntime` indicate interactions with more general V8 functionality.
    * **Builtins:** Calls to `CallBuiltin` suggest calls to pre-compiled V8 functions for common operations.

6. **Infer the overall purpose:** Based on the individual handlers and common operations, the file's primary function is to provide the implementation for each bytecode instruction of V8's interpreter (Ignition). It defines how each bytecode manipulates data (registers, accumulator, memory), performs operations (loads, stores, property access, function calls), and interacts with the V8 runtime.

7. **Address the ".tq" question:** The prompt asks about `.tq` files. Based on general V8 knowledge (and if I didn't know, a quick search would confirm), `.tq` files are related to Torque, V8's type-safe TypeScript-like language for generating C++ code. The prompt provides the answer: if the file ended in `.tq`, it would be a Torque source file.

8. **Connect to JavaScript functionality:** The bytecodes implemented in this file directly correspond to the operations performed when executing JavaScript code. Provide examples of common JavaScript operations and link them to potential bytecodes (e.g., variable assignment to `Star`, property access to `GetNamedProperty`).

9. **Consider code logic and examples:**  For simpler handlers like `LdaSmi`, provide an example of how the immediate operand is used. For more complex ones like `GetNamedProperty`, illustrate the flow with a sample JavaScript code snippet and explain how the handler would access the object, property name, and feedback vector.

10. **Think about common programming errors:** Relate the file's functionality to potential JavaScript errors. For instance, incorrect variable names could lead to `LdaLookupSlot` failing or triggering runtime errors.

11. **Synthesize the summary:** Combine all the observations into a concise summary of the file's functionality, highlighting its role in interpreting bytecode instructions.

12. **Structure the answer:** Organize the information clearly, addressing each point raised in the prompt (functionality, `.tq` files, JavaScript relationship, code logic, common errors). Use formatting (like bullet points or numbered lists) to improve readability.
```javascript
// 假设我们有以下 JavaScript 代码
function example() {
  let x = 10; // 对应 Star 或 StaCurrentContextSlot 等
  return x + 5; // 对应 Ldar, LdaSmi, Add 等
}

let obj = { a: 1 }; // 对应 CreateObject, SetNamedProperty 等
let y = obj.a; // 对应 GetNamedProperty

function globalFunction() {
  globalVar = 20; // 对应 StaGlobal
  return globalVar; // 对应 LdaGlobal
}
```

## v8/src/interpreter/interpreter-generator.cc 功能归纳 (第 1 部分)

这是 V8 JavaScript 引擎中负责 **生成解释器 (Ignition) 代码** 的一个 C++ 源文件。它定义了 **各种字节码指令的处理逻辑**，这些指令是 V8 执行 JavaScript 代码的中间表示形式。

**主要功能包括：**

1. **定义字节码处理器的结构：** 使用 `IGNITION_HANDLER` 宏为每个字节码指令定义一个处理类，这些类继承自 `InterpreterAssembler` 或其派生类，并包含一个 `GenerateImpl` 方法来实现该字节码的具体执行逻辑。

2. **实现各种加载 (Load) 操作：**  包含加载字面量 (如 `LdaZero`, `LdaSmi`, `LdaConstant`, `LdaUndefined`, `LdaNull`, `LdaTrue`, `LdaFalse`)、寄存器值 (`Ldar`)、全局变量 (`LdaGlobal`, `LdaGlobalInsideTypeof`, `LdaLookupGlobalSlot`)、上下文变量 (`LdaContextSlot`, `LdaCurrentContextSlot`, `LdaLookupSlot`) 以及模块变量 (`LdaModuleVariable`) 的指令处理器。

3. **实现各种存储 (Store) 操作：**  包含存储到寄存器 (`Star`, `Star0`)、全局变量 (`StaGlobal`)、上下文变量 (`StaContextSlot`, `StaCurrentContextSlot`) 以及动态属性查找结果 (`StaLookupSlot`) 的指令处理器。

4. **实现属性访问操作：**  包括获取命名属性 (`GetNamedProperty`, `GetNamedPropertyFromSuper`) 和键值属性 (`GetKeyedProperty`, `GetEnumeratedKeyedProperty`) 的指令处理器，这些处理器会调用相应的 IC (Inline Cache) 系统进行优化。

5. **实现属性设置和定义操作：** 包括设置命名属性 (`SetNamedProperty`, `DefineNamedOwnProperty`)、设置键值属性 (`SetKeyedProperty`, `DefineKeyedOwnProperty`) 以及在数组字面量中存储元素 (`StaInArrayLiteral`) 的指令处理器，同样会利用 IC 系统。

6. **处理模块相关的加载操作：**  包含加载模块变量的指令处理器 (`LdaModuleVariable`)。

7. **与 V8 运行时 (Runtime) 和内置函数 (Builtins) 交互：**  许多指令处理器会调用 V8 的运行时函数 (例如 `CallRuntime(Runtime::kLoadLookupSlot, ...)` ) 或内置函数 (例如 `CallBuiltin(Builtin::kStoreGlobalIC, ...)` ) 来完成更复杂的操作。

8. **处理 `typeof` 运算符：**  提供了 `LdaGlobalInsideTypeof` 和 `LdaLookupSlotInsideTypeof` 等特殊指令处理器，用于在执行 `typeof` 运算符时避免抛出 `ReferenceError`。

9. **快速路径和慢速路径优化：**  在某些操作中 (如 `LdaLookupContextSlot`, `LdaLookupGlobalSlot`)，代码会尝试执行快速路径 (直接加载)，如果条件不满足 (例如存在上下文扩展)，则会跳转到慢速路径调用运行时函数。

**关于 .tq 结尾：**

如果 `v8/src/interpreter/interpreter-generator.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码，通常用于实现内置函数和解释器/编译器的一部分。当前提供的代码是 `.cc` 文件，表明它是手写的 C++ 代码。

**与 JavaScript 功能的关系和 JavaScript 示例：**

该文件中的每个 `IGNITION_HANDLER` 对应的字节码指令都直接映射到 JavaScript 代码的执行。当 V8 解释执行 JavaScript 代码时，会将代码编译成字节码，然后由这里定义的处理器来执行。

**代码逻辑推理和假设输入输出：**

以 `LdaSmi` 为例：

* **假设输入：**  一个包含 `LdaSmi` 字节码的字节码流，并且该字节码的操作数 `imm` (immediate) 为 `5`。
* **输出：**  执行 `LdaSmi` 处理器后，累加器 (Accumulator) 寄存器将包含一个值为 `5` 的 Smi (Small Integer) 对象。

以 `GetNamedProperty` 为例：

* **假设输入：**  执行 `get obj.a;` 这段 JavaScript 代码生成的字节码，当前执行到 `GetNamedProperty` 指令，寄存器中存储着对象 `obj`，常量池中存储着属性名 `"a"`，反馈向量中可能包含用于优化的信息。
* **输出：**  执行 `GetNamedProperty` 处理器后，会尝试从 `obj` 中加载名为 `"a"` 的属性值。如果成功，累加器将包含属性值 `1`。如果属性不存在或访问过程中触发了其他行为 (如 getter)，则累加器可能包含不同的结果，并且可能会触发 IC 的更新。

**涉及用户常见的编程错误：**

1. **访问未定义的变量：** 例如，在 JavaScript 中使用一个未声明或未初始化的变量会导致 `ReferenceError`。在解释器层面，这可能涉及到 `LdaLookupSlot` 或 `LdaGlobal` 等指令，如果查找失败，则会抛出异常。

   ```javascript
   function example() {
     console.log(unknownVariable); // 可能会触发 LdaLookupSlot 失败
   }
   ```

2. **尝试给只读属性赋值：**  例如，尝试修改一个使用 `const` 声明的变量或对象的不可写属性。这在解释器层面会涉及到 `SetNamedProperty` 或 `SetKeyedProperty` 等指令，但由于属性的特性，赋值操作会失败或抛出 `TypeError`。

   ```javascript
   const PI = 3.14;
   PI = 3.15; // 可能会触发 SetNamedProperty 失败并抛出 TypeError
   ```

3. **对 `null` 或 `undefined` 进行属性访问：**  这是一个常见的错误，会导致 `TypeError`。在解释器层面，当执行 `GetNamedProperty` 或 `GetKeyedProperty` 时，如果接收者是 `null` 或 `undefined`，会触发相应的错误处理逻辑。

   ```javascript
   let obj = null;
   let x = obj.a; // 可能会触发 GetNamedProperty 时的 TypeError
   ```

总而言之，`v8/src/interpreter/interpreter-generator.cc` 是 V8 解释器 Ignition 的核心组成部分，它详细定义了 JavaScript 字节码指令的执行语义，是 V8 执行 JavaScript 代码的基础。

Prompt: 
```
这是目录为v8/src/interpreter/interpreter-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/interpreter-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/interpreter/interpreter-generator.h"

#include <array>
#include <tuple>

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/profile-data-reader.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/compiler/linkage.h"
#include "src/compiler/pipeline.h"
#include "src/compiler/turboshaft/builtin-compiler.h"
#include "src/ic/accessor-assembler.h"
#include "src/ic/binary-op-assembler.h"
#include "src/ic/ic.h"
#include "src/ic/unary-op-assembler.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/interpreter/bytecodes.h"
#include "src/interpreter/interpreter-assembler.h"
#include "src/interpreter/interpreter-generator-tsa.h"
#include "src/interpreter/interpreter-intrinsics-generator.h"
#include "src/objects/cell.h"
#include "src/objects/js-generator.h"
#include "src/objects/objects-inl.h"
#include "src/objects/oddball.h"
#include "src/objects/shared-function-info.h"
#include "src/objects/source-text-module.h"
#include "src/utils/ostreams.h"
#include "torque-generated/exported-macros-assembler.h"

namespace v8 {
namespace internal {
namespace interpreter {

#include "src/codegen/define-code-stub-assembler-macros.inc"

namespace {

using compiler::CodeAssemblerState;
using Label = CodeStubAssembler::Label;

#define IGNITION_HANDLER(Name, BaseAssembler)                         \
  class Name##Assembler : public BaseAssembler {                      \
   public:                                                            \
    explicit Name##Assembler(compiler::CodeAssemblerState* state,     \
                             Bytecode bytecode, OperandScale scale)   \
        : BaseAssembler(state, bytecode, scale) {}                    \
    Name##Assembler(const Name##Assembler&) = delete;                 \
    Name##Assembler& operator=(const Name##Assembler&) = delete;      \
    static void Generate(compiler::CodeAssemblerState* state,         \
                         OperandScale scale);                         \
                                                                      \
   private:                                                           \
    void GenerateImpl();                                              \
  };                                                                  \
  void Name##Assembler::Generate(compiler::CodeAssemblerState* state, \
                                 OperandScale scale) {                \
    Name##Assembler assembler(state, Bytecode::k##Name, scale);       \
    state->SetInitialDebugInformation(#Name, __FILE__, __LINE__);     \
    assembler.GenerateImpl();                                         \
  }                                                                   \
  void Name##Assembler::GenerateImpl()

// LdaZero
//
// Load literal '0' into the accumulator.
IGNITION_HANDLER(LdaZero, InterpreterAssembler) {
  TNode<Number> zero_value = NumberConstant(0.0);
  SetAccumulator(zero_value);
  Dispatch();
}

// LdaSmi <imm>
//
// Load an integer literal into the accumulator as a Smi.
IGNITION_HANDLER(LdaSmi, InterpreterAssembler) {
  TNode<Smi> smi_int = BytecodeOperandImmSmi(0);
  SetAccumulator(smi_int);
  Dispatch();
}

// LdaConstant <idx>
//
// Load constant literal at |idx| in the constant pool into the accumulator.
IGNITION_HANDLER(LdaConstant, InterpreterAssembler) {
  TNode<Object> constant = LoadConstantPoolEntryAtOperandIndex(0);
  SetAccumulator(constant);
  Dispatch();
}

// LdaUndefined
//
// Load Undefined into the accumulator.
IGNITION_HANDLER(LdaUndefined, InterpreterAssembler) {
  SetAccumulator(UndefinedConstant());
  Dispatch();
}

// LdaNull
//
// Load Null into the accumulator.
IGNITION_HANDLER(LdaNull, InterpreterAssembler) {
  SetAccumulator(NullConstant());
  Dispatch();
}

// LdaTheHole
//
// Load TheHole into the accumulator.
IGNITION_HANDLER(LdaTheHole, InterpreterAssembler) {
  SetAccumulator(TheHoleConstant());
  Dispatch();
}

// LdaTrue
//
// Load True into the accumulator.
IGNITION_HANDLER(LdaTrue, InterpreterAssembler) {
  SetAccumulator(TrueConstant());
  Dispatch();
}

// LdaFalse
//
// Load False into the accumulator.
IGNITION_HANDLER(LdaFalse, InterpreterAssembler) {
  SetAccumulator(FalseConstant());
  Dispatch();
}

// Ldar <src>
//
// Load accumulator with value from register <src>.
IGNITION_HANDLER(Ldar, InterpreterAssembler) {
  TNode<Object> value = LoadRegisterAtOperandIndex(0);
  SetAccumulator(value);
  Dispatch();
}

// Star <dst>
//
// Store accumulator to register <dst>.
IGNITION_HANDLER(Star, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  StoreRegisterAtOperandIndex(accumulator, 0);
  Dispatch();
}

// Star0 - StarN
//
// Store accumulator to one of a special batch of registers, without using a
// second byte to specify the destination.
//
// Even though this handler is declared as Star0, multiple entries in
// the jump table point to this handler.
IGNITION_HANDLER(Star0, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  TNode<WordT> opcode = LoadBytecode(BytecodeOffset());
  StoreRegisterForShortStar(accumulator, opcode);
  Dispatch();
}

// Mov <src> <dst>
//
// Stores the value of register <src> to register <dst>.
IGNITION_HANDLER(Mov, InterpreterAssembler) {
  TNode<Object> src_value = LoadRegisterAtOperandIndex(0);
  StoreRegisterAtOperandIndex(src_value, 1);
  Dispatch();
}

class InterpreterLoadGlobalAssembler : public InterpreterAssembler {
 public:
  InterpreterLoadGlobalAssembler(CodeAssemblerState* state, Bytecode bytecode,
                                 OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void LdaGlobal(int slot_operand_index, int name_operand_index,
                 TypeofMode typeof_mode) {
    TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();

    AccessorAssembler accessor_asm(state());
    ExitPoint exit_point(this, [=, this](TNode<Object> result) {
      SetAccumulator(result);
      Dispatch();
    });

    LazyNode<TaggedIndex> lazy_slot = [=, this] {
      return BytecodeOperandIdxTaggedIndex(slot_operand_index);
    };

    LazyNode<Context> lazy_context = [=, this] { return GetContext(); };

    LazyNode<Name> lazy_name = [=, this] {
      TNode<Name> name =
          CAST(LoadConstantPoolEntryAtOperandIndex(name_operand_index));
      return name;
    };

    accessor_asm.LoadGlobalIC(maybe_feedback_vector, lazy_slot, lazy_context,
                              lazy_name, typeof_mode, &exit_point);
  }
};

// LdaGlobal <name_index> <slot>
//
// Load the global with name in constant pool entry <name_index> into the
// accumulator using FeedBackVector slot <slot> outside of a typeof.
IGNITION_HANDLER(LdaGlobal, InterpreterLoadGlobalAssembler) {
  static const int kNameOperandIndex = 0;
  static const int kSlotOperandIndex = 1;

  LdaGlobal(kSlotOperandIndex, kNameOperandIndex, TypeofMode::kNotInside);
}

// LdaGlobalInsideTypeof <name_index> <slot>
//
// Load the global with name in constant pool entry <name_index> into the
// accumulator using FeedBackVector slot <slot> inside of a typeof.
IGNITION_HANDLER(LdaGlobalInsideTypeof, InterpreterLoadGlobalAssembler) {
  static const int kNameOperandIndex = 0;
  static const int kSlotOperandIndex = 1;

  LdaGlobal(kSlotOperandIndex, kNameOperandIndex, TypeofMode::kInside);
}

// StaGlobal <name_index> <slot>
//
// Store the value in the accumulator into the global with name in constant pool
// entry <name_index> using FeedBackVector slot <slot>.
IGNITION_HANDLER(StaGlobal, InterpreterAssembler) {
  TNode<Context> context = GetContext();

  // Store the global via the StoreGlobalIC.
  TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<Object> value = GetAccumulator();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<HeapObject> maybe_vector = LoadFeedbackVector();

  TNode<Object> result = CallBuiltin(Builtin::kStoreGlobalIC, context, name,
                                     value, slot, maybe_vector);
  // To avoid special logic in the deoptimizer to re-materialize the value in
  // the accumulator, we clobber the accumulator after the IC call. It
  // doesn't really matter what we write to the accumulator here, since we
  // restore to the correct value on the outside. Storing the result means we
  // don't need to keep unnecessary state alive across the callstub.
  ClobberAccumulator(result);

  Dispatch();
}

// LdaContextSlot <context> <slot_index> <depth>
//
// Load the object in |slot_index| of the context at |depth| in the context
// chain starting at |context| into the accumulator.
IGNITION_HANDLER(LdaContextSlot, InterpreterAssembler) {
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(1));
  TNode<Uint32T> depth = BytecodeOperandUImm(2);
  TNode<Context> slot_context = GetContextAtDepth(context, depth);
  TNode<Object> result = LoadContextElement(slot_context, slot_index);
  SetAccumulator(result);
  Dispatch();
}

// LdaScriptContextSlot <context> <slot_index> <depth>
//
// Load the object in |slot_index| of the context at |depth| in the context
// chain starting at |context| into the accumulator.
IGNITION_HANDLER(LdaScriptContextSlot, InterpreterAssembler) {
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(1));
  TNode<Uint32T> depth = BytecodeOperandUImm(2);
  TNode<Context> slot_context = GetContextAtDepth(context, depth);
  TNode<Object> result = LoadScriptContextElement(slot_context, slot_index);
  SetAccumulator(result);
  Dispatch();
}

// LdaImmutableContextSlot <context> <slot_index> <depth>
//
// Load the object in |slot_index| of the context at |depth| in the context
// chain starting at |context| into the accumulator.
IGNITION_HANDLER(LdaImmutableContextSlot, InterpreterAssembler) {
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(1));
  TNode<Uint32T> depth = BytecodeOperandUImm(2);
  TNode<Context> slot_context = GetContextAtDepth(context, depth);
  TNode<Object> result = LoadContextElement(slot_context, slot_index);
  SetAccumulator(result);
  Dispatch();
}

// LdaCurrentContextSlot <slot_index>
//
// Load the object in |slot_index| of the current context into the accumulator.
IGNITION_HANDLER(LdaCurrentContextSlot, InterpreterAssembler) {
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(0));
  TNode<Context> slot_context = GetContext();
  TNode<Object> result = LoadContextElement(slot_context, slot_index);
  SetAccumulator(result);
  Dispatch();
}

// LdaCurrentScriptContextSlot <slot_index>
//
// Load the object in |slot_index| of the current context into the accumulator.
IGNITION_HANDLER(LdaCurrentScriptContextSlot, InterpreterAssembler) {
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(0));
  TNode<Context> slot_context = GetContext();
  TNode<Object> result = LoadScriptContextElement(slot_context, slot_index);
  SetAccumulator(result);
  Dispatch();
}

// LdaImmutableCurrentContextSlot <slot_index>
//
// Load the object in |slot_index| of the current context into the accumulator.
IGNITION_HANDLER(LdaImmutableCurrentContextSlot, InterpreterAssembler) {
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(0));
  TNode<Context> slot_context = GetContext();
  TNode<Object> result = LoadContextElement(slot_context, slot_index);
  SetAccumulator(result);
  Dispatch();
}

// StaContextSlot <context> <slot_index> <depth>
//
// Stores the object in the accumulator into |slot_index| of the context at
// |depth| in the context chain starting at |context|.
IGNITION_HANDLER(StaContextSlot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(1));
  TNode<Uint32T> depth = BytecodeOperandUImm(2);
  TNode<Context> slot_context = GetContextAtDepth(context, depth);
  StoreContextElement(slot_context, slot_index, value);
  Dispatch();
}

// StaCurrentContextSlot <slot_index>
//
// Stores the object in the accumulator into |slot_index| of the current
// context.
IGNITION_HANDLER(StaCurrentContextSlot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(0));
  TNode<Context> slot_context = GetContext();
  StoreContextElement(slot_context, slot_index, value);
  Dispatch();
}

// StaScriptContextSlot <context> <slot_index> <depth>
//
// Stores the object in the accumulator into |slot_index| of the script context
// at |depth| in the context chain starting at |context|.
IGNITION_HANDLER(StaScriptContextSlot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(1));
  TNode<Uint32T> depth = BytecodeOperandUImm(2);
  TNode<Context> slot_context = GetContextAtDepth(context, depth);
  StoreContextElementAndUpdateSideData(slot_context, slot_index, value);
  Dispatch();
}

// StaCurrentScriptContextSlot <slot_index>
//
// Stores the object in the accumulator into |slot_index| of the current
// context (which has to be a script context).
IGNITION_HANDLER(StaCurrentScriptContextSlot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(0));
  TNode<Context> slot_context = GetContext();
  StoreContextElementAndUpdateSideData(slot_context, slot_index, value);
  Dispatch();
}

// LdaLookupSlot <name_index>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically.
IGNITION_HANDLER(LdaLookupSlot, InterpreterAssembler) {
  TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<Context> context = GetContext();
  TNode<Object> result = CallRuntime(Runtime::kLoadLookupSlot, context, name);
  SetAccumulator(result);
  Dispatch();
}

// LdaLookupSlotInsideTypeof <name_index>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically without causing a NoReferenceError.
IGNITION_HANDLER(LdaLookupSlotInsideTypeof, InterpreterAssembler) {
  TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallRuntime(Runtime::kLoadLookupSlotInsideTypeof, context, name);
  SetAccumulator(result);
  Dispatch();
}

class InterpreterLookupContextSlotAssembler : public InterpreterAssembler {
 public:
  InterpreterLookupContextSlotAssembler(CodeAssemblerState* state,
                                        Bytecode bytecode,
                                        OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void LookupContextSlot(Runtime::FunctionId function_id, ContextKind kind) {
    TNode<Context> context = GetContext();
    TNode<IntPtrT> slot_index = Signed(BytecodeOperandIdx(1));
    TNode<Uint32T> depth = BytecodeOperandUImm(2);

    Label slowpath(this, Label::kDeferred);

    // Check for context extensions to allow the fast path.
    TNode<Context> slot_context =
        GotoIfHasContextExtensionUpToDepth(context, depth, &slowpath);

    // Fast path does a normal load context.
    {
      TNode<Object> result =
          (kind == ContextKind::kScriptContext)
              ? LoadScriptContextElement(slot_context, slot_index)
              : LoadContextElement(slot_context, slot_index);
      SetAccumulator(result);
      Dispatch();
    }

    // Slow path when we have to call out to the runtime.
    BIND(&slowpath);
    {
      TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
      TNode<Object> result = CallRuntime(function_id, context, name);
      SetAccumulator(result);
      Dispatch();
    }
  }
};

// LdaLookupContextSlot <name_index>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically.
IGNITION_HANDLER(LdaLookupContextSlot, InterpreterLookupContextSlotAssembler) {
  LookupContextSlot(Runtime::kLoadLookupSlot, ContextKind::kDefault);
}

// LdaLookupScriptContextSlot <name_index>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically.
IGNITION_HANDLER(LdaLookupScriptContextSlot,
                 InterpreterLookupContextSlotAssembler) {
  LookupContextSlot(Runtime::kLoadLookupSlot, ContextKind::kScriptContext);
}

// LdaLookupContextSlotInsideTypeof <name_index>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically without causing a NoReferenceError.
IGNITION_HANDLER(LdaLookupContextSlotInsideTypeof,
                 InterpreterLookupContextSlotAssembler) {
  LookupContextSlot(Runtime::kLoadLookupSlotInsideTypeof,
                    ContextKind::kDefault);
}

// LdaLookupScriptContextSlotInsideTypeof <name_index>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically without causing a NoReferenceError.
IGNITION_HANDLER(LdaLookupScriptContextSlotInsideTypeof,
                 InterpreterLookupContextSlotAssembler) {
  LookupContextSlot(Runtime::kLoadLookupSlotInsideTypeof,
                    ContextKind::kScriptContext);
}

class InterpreterLookupGlobalAssembler : public InterpreterLoadGlobalAssembler {
 public:
  InterpreterLookupGlobalAssembler(CodeAssemblerState* state, Bytecode bytecode,
                                   OperandScale operand_scale)
      : InterpreterLoadGlobalAssembler(state, bytecode, operand_scale) {}

  void LookupGlobalSlot(Runtime::FunctionId function_id) {
    TNode<Context> context = GetContext();
    TNode<Uint32T> depth = BytecodeOperandUImm(2);

    Label slowpath(this, Label::kDeferred);

    // Check for context extensions to allow the fast path
    GotoIfHasContextExtensionUpToDepth(context, depth, &slowpath);

    // Fast path does a normal load global
    {
      static const int kNameOperandIndex = 0;
      static const int kSlotOperandIndex = 1;

      TypeofMode typeof_mode =
          function_id == Runtime::kLoadLookupSlotInsideTypeof
              ? TypeofMode::kInside
              : TypeofMode::kNotInside;

      LdaGlobal(kSlotOperandIndex, kNameOperandIndex, typeof_mode);
    }

    // Slow path when we have to call out to the runtime
    BIND(&slowpath);
    {
      TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
      TNode<Object> result = CallRuntime(function_id, context, name);
      SetAccumulator(result);
      Dispatch();
    }
  }
};

// LdaLookupGlobalSlot <name_index> <feedback_slot> <depth>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically.
IGNITION_HANDLER(LdaLookupGlobalSlot, InterpreterLookupGlobalAssembler) {
  LookupGlobalSlot(Runtime::kLoadLookupSlot);
}

// LdaLookupGlobalSlotInsideTypeof <name_index> <feedback_slot> <depth>
//
// Lookup the object with the name in constant pool entry |name_index|
// dynamically without causing a NoReferenceError.
IGNITION_HANDLER(LdaLookupGlobalSlotInsideTypeof,
                 InterpreterLookupGlobalAssembler) {
  LookupGlobalSlot(Runtime::kLoadLookupSlotInsideTypeof);
}

// StaLookupSlot <name_index> <flags>
//
// Store the object in accumulator to the object with the name in constant
// pool entry |name_index|.
IGNITION_HANDLER(StaLookupSlot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(0));
  TNode<Uint32T> bytecode_flags = BytecodeOperandFlag8(1);
  TNode<Context> context = GetContext();
  TVARIABLE(Object, var_result);

  Label sloppy(this), strict(this), end(this);
  DCHECK_EQ(0, LanguageMode::kSloppy);
  DCHECK_EQ(1, LanguageMode::kStrict);
  DCHECK_EQ(0, static_cast<int>(LookupHoistingMode::kNormal));
  DCHECK_EQ(1, static_cast<int>(LookupHoistingMode::kLegacySloppy));
  Branch(IsSetWord32<StoreLookupSlotFlags::LanguageModeBit>(bytecode_flags),
         &strict, &sloppy);

  BIND(&strict);
  {
    CSA_DCHECK(this, IsClearWord32<StoreLookupSlotFlags::LookupHoistingModeBit>(
                         bytecode_flags));
    var_result =
        CallRuntime(Runtime::kStoreLookupSlot_Strict, context, name, value);
    Goto(&end);
  }

  BIND(&sloppy);
  {
    Label hoisting(this), ordinary(this);
    Branch(IsSetWord32<StoreLookupSlotFlags::LookupHoistingModeBit>(
               bytecode_flags),
           &hoisting, &ordinary);

    BIND(&hoisting);
    {
      var_result = CallRuntime(Runtime::kStoreLookupSlot_SloppyHoisting,
                               context, name, value);
      Goto(&end);
    }

    BIND(&ordinary);
    {
      var_result =
          CallRuntime(Runtime::kStoreLookupSlot_Sloppy, context, name, value);
      Goto(&end);
    }
  }

  BIND(&end);
  {
    SetAccumulator(var_result.value());
    Dispatch();
  }
}

// GetNamedProperty <object> <name_index> <slot>
//
// Calls the LoadIC at FeedBackVector slot <slot> for <object> and the name at
// constant pool entry <name_index>.
IGNITION_HANDLER(GetNamedProperty, InterpreterAssembler) {
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();

  // Load receiver.
  TNode<Object> recv = LoadRegisterAtOperandIndex(0);

  // Load the name and context lazily.
  LazyNode<TaggedIndex> lazy_slot = [=, this] {
    return BytecodeOperandIdxTaggedIndex(2);
  };
  LazyNode<Name> lazy_name = [=, this] {
    return CAST(LoadConstantPoolEntryAtOperandIndex(1));
  };
  LazyNode<Context> lazy_context = [=, this] { return GetContext(); };

  Label done(this);
  TVARIABLE(Object, var_result);
  ExitPoint exit_point(this, &done, &var_result);

  AccessorAssembler::LazyLoadICParameters params(lazy_context, recv, lazy_name,
                                                 lazy_slot, feedback_vector);
  AccessorAssembler accessor_asm(state());
  accessor_asm.LoadIC_BytecodeHandler(&params, &exit_point);

  BIND(&done);
  {
    SetAccumulator(var_result.value());
    Dispatch();
  }
}

// GetNamedPropertyFromSuper <receiver> <name_index> <slot>
//
// Calls the LoadSuperIC at FeedBackVector slot <slot> for <receiver>, home
// object's prototype (home object in the accumulator) and the name at constant
// pool entry <name_index>.
IGNITION_HANDLER(GetNamedPropertyFromSuper, InterpreterAssembler) {
  TNode<Object> receiver = LoadRegisterAtOperandIndex(0);
  TNode<HeapObject> home_object = CAST(GetAccumulator());
  TNode<Object> home_object_prototype = LoadMapPrototype(LoadMap(home_object));
  TNode<Object> name = LoadConstantPoolEntryAtOperandIndex(1);
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(2);
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TNode<Object> result =
      CallBuiltin(Builtin::kLoadSuperIC, context, receiver,
                  home_object_prototype, name, slot, feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

// GetKeyedProperty <object> <slot>
//
// Calls the KeyedLoadIC at FeedBackVector slot <slot> for <object> and the key
// in the accumulator.
IGNITION_HANDLER(GetKeyedProperty, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> name = GetAccumulator();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(1);
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TVARIABLE(Object, var_result);
  var_result = CallBuiltin(Builtin::kKeyedLoadIC, context, object, name, slot,
                           feedback_vector);
  SetAccumulator(var_result.value());
  Dispatch();
}

// GetEnumeratedKeyedProperty <object> <enum_index> <cache_type> <slot>
//
// Calls the EnumeratedKeyedLoadIC at FeedBackVector slot <slot> for <object>
// and the key in the accumulator. The key is coming from the each target of a
// for-in loop.
IGNITION_HANDLER(GetEnumeratedKeyedProperty, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> name = GetAccumulator();
  TNode<Smi> enum_index = CAST(LoadRegisterAtOperandIndex(1));
  TNode<Object> cache_type = LoadRegisterAtOperandIndex(2);
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(3);
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TVARIABLE(Object, var_result);
  var_result = CallBuiltin(Builtin::kEnumeratedKeyedLoadIC, context, object,
                           name, enum_index, cache_type, slot, feedback_vector);
  SetAccumulator(var_result.value());
  Dispatch();
}

class InterpreterSetNamedPropertyAssembler : public InterpreterAssembler {
 public:
  InterpreterSetNamedPropertyAssembler(CodeAssemblerState* state,
                                       Bytecode bytecode,
                                       OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void SetNamedProperty(Builtin ic_bultin, NamedPropertyType property_type) {
    TNode<Object> object = LoadRegisterAtOperandIndex(0);
    TNode<Name> name = CAST(LoadConstantPoolEntryAtOperandIndex(1));
    TNode<Object> value = GetAccumulator();
    TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(2);
    TNode<HeapObject> maybe_vector = LoadFeedbackVector();
    TNode<Context> context = GetContext();

    TNode<Object> result = CallBuiltin(ic_bultin, context, object, name, value,
                                       slot, maybe_vector);
    // To avoid special logic in the deoptimizer to re-materialize the value in
    // the accumulator, we clobber the accumulator after the IC call. It
    // doesn't really matter what we write to the accumulator here, since we
    // restore to the correct value on the outside. Storing the result means we
    // don't need to keep unnecessary state alive across the callstub.
    ClobberAccumulator(result);
    Dispatch();
  }
};

// SetNamedProperty <object> <name_index> <slot>
//
// Calls the StoreIC at FeedBackVector slot <slot> for <object> and
// the name in constant pool entry <name_index> with the value in the
// accumulator.
IGNITION_HANDLER(SetNamedProperty, InterpreterSetNamedPropertyAssembler) {
  // StoreIC is currently a base class for multiple property store operations
  // and contains mixed logic for named and keyed, set and define operations,
  // the paths are controlled by feedback.
  // TODO(v8:12548): refactor SetNamedIC as a subclass of StoreIC, which can be
  // called here.
  SetNamedProperty(Builtin::kStoreIC, NamedPropertyType::kNotOwn);
}

// DefineNamedOwnProperty <object> <name_index> <slot>
//
// Calls the DefineNamedOwnIC at FeedBackVector slot <slot> for <object> and
// the name in constant pool entry <name_index> with the value in the
// accumulator.
IGNITION_HANDLER(DefineNamedOwnProperty, InterpreterSetNamedPropertyAssembler) {
  SetNamedProperty(Builtin::kDefineNamedOwnIC, NamedPropertyType::kOwn);
}

// SetKeyedProperty <object> <key> <slot>
//
// Calls the KeyedStoreIC at FeedbackVector slot <slot> for <object> and
// the key <key> with the value in the accumulator. This could trigger
// the setter and the set traps if necessary.
IGNITION_HANDLER(SetKeyedProperty, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> name = LoadRegisterAtOperandIndex(1);
  TNode<Object> value = GetAccumulator();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(2);
  TNode<HeapObject> maybe_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  // KeyedStoreIC is currently a base class for multiple keyed property store
  // operations and contains mixed logic for set and define operations,
  // the paths are controlled by feedback.
  // TODO(v8:12548): refactor SetKeyedIC as a subclass of KeyedStoreIC, which
  // can be called here.
  TNode<Object> result = CallBuiltin(Builtin::kKeyedStoreIC, context, object,
                                     name, value, slot, maybe_vector);
  // To avoid special logic in the deoptimizer to re-materialize the value in
  // the accumulator, we clobber the accumulator after the IC call. It
  // doesn't really matter what we write to the accumulator here, since we
  // restore to the correct value on the outside. Storing the result means we
  // don't need to keep unnecessary state alive across the callstub.
  ClobberAccumulator(result);
  Dispatch();
}

// DefineKeyedOwnProperty <object> <key> <flags> <slot>
//
// Calls the DefineKeyedOwnIC at FeedbackVector slot <slot> for <object> and
// the key <key> with the value in the accumulator. Whether set_function_name
// is stored in DefineKeyedOwnPropertyFlags <flags>.
//
// This is similar to SetKeyedProperty, but avoids checking the prototype
// chain, and in the case of private names, throws if the private name already
// exists.
IGNITION_HANDLER(DefineKeyedOwnProperty, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> name = LoadRegisterAtOperandIndex(1);
  TNode<Object> value = GetAccumulator();
  TNode<Smi> flags =
      SmiFromInt32(UncheckedCast<Int32T>(BytecodeOperandFlag8(2)));
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(3);
  TNode<HeapObject> maybe_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TNode<Object> result =
      CallBuiltin(Builtin::kDefineKeyedOwnIC, context, object, name, value,
                  flags, slot, maybe_vector);
  // To avoid special logic in the deoptimizer to re-materialize the value in
  // the accumulator, we clobber the accumulator after the IC call. It
  // doesn't really matter what we write to the accumulator here, since we
  // restore to the correct value on the outside. Storing the result means we
  // don't need to keep unnecessary state alive across the callstub.
  ClobberAccumulator(result);
  Dispatch();
}

// StaInArrayLiteral <array> <index> <slot>
//
// Calls the StoreInArrayLiteralIC at FeedbackVector slot <slot> for <array> and
// the key <index> with the value in the accumulator.
IGNITION_HANDLER(StaInArrayLiteral, InterpreterAssembler) {
  TNode<Object> array = LoadRegisterAtOperandIndex(0);
  TNode<Object> index = LoadRegisterAtOperandIndex(1);
  TNode<Object> value = GetAccumulator();
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(2);
  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  TNode<Object> result =
      CallBuiltin(Builtin::kStoreInArrayLiteralIC, context, array, index, value,
                  slot, feedback_vector);
  // To avoid special logic in the deoptimizer to re-materialize the value in
  // the accumulator, we clobber the accumulator after the IC call. It
  // doesn't really matter what we write to the accumulator here, since we
  // restore to the correct value on the outside. Storing the result means we
  // don't need to keep unnecessary state alive across the callstub.
  ClobberAccumulator(result);
  Dispatch();
}

// DefineKeyedOwnPropertyInLiteral <object> <name> <flags> <slot>
//
// Define a property <name> with value from the accumulator in <object>.
// Property attributes and whether set_function_name are stored in
// DefineKeyedOwnPropertyInLiteralFlags <flags>.
//
// This definition is not observable and is used only for definitions
// in object or class literals.
IGNITION_HANDLER(DefineKeyedOwnPropertyInLiteral, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> name = LoadRegisterAtOperandIndex(1);
  TNode<Object> value = GetAccumulator();
  TNode<Smi> flags =
      SmiFromInt32(UncheckedCast<Int32T>(BytecodeOperandFlag8(2)));
  TNode<TaggedIndex> slot = BytecodeOperandIdxTaggedIndex(3);

  TNode<HeapObject> feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();

  CallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral, context, object, name,
              value, flags, feedback_vector, slot);
  Dispatch();
}

// LdaModuleVariable <cell_index> <depth>
//
// Load the contents of a module variable into the accumulator.  The variable is
// identified by <cell_index>.  <depth> is the depth of the current context
// relative to the module context.
IGNITION_HANDLER(LdaModuleVariable, InterpreterAssembler) {
  TNode<IntPtrT> cell_index = BytecodeOperandImmIntPtr(0);
  TNode<Uint32T> depth = BytecodeOperandUImm(1);

  TNode<Context> module_context = GetContextAtDepth(GetContext(), depth);
  TNode<SourceTextModule> module =
      CAST(LoadContextElement(module_context, C
"""


```