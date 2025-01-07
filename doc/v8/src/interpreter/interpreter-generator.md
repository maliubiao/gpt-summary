Response: The user wants a summary of the C++ source code file `v8/src/interpreter/interpreter-generator.cc`. The summary should focus on the functionality of the file. If the functionality is related to JavaScript, an illustrative JavaScript example should be provided. This is the first part of a two-part file.

**Plan:**

1. Read through the provided C++ code.
2. Identify the main purpose and responsibilities of the code. It seems to be defining handlers for various bytecode instructions used by V8's interpreter.
3. Group related functionalities together.
4. For functionalities that directly relate to JavaScript operations, create simple JavaScript examples.
5. Focus on summarizing the functionality in this first part, keeping in mind that there's a second part.
这个C++源代码文件 (`v8/src/interpreter/interpreter-generator.cc`) 的主要功能是 **为V8 JavaScript引擎的解释器生成处理各种字节码指令的代码**。

更具体地说，这个文件定义了一系列的 "handlers" (处理程序)，每个 handler 对应一个特定的字节码指令。当解释器执行这些字节码指令时，会调用相应的 handler 来完成指令的功能。

这些 handler 使用 V8 的内部 API（例如 `InterpreterAssembler`, `CodeStubAssembler`, `Builtin` 等）来生成机器码，以实现诸如：

*   加载常量、变量和上下文中的值到累加器 (accumulator)。
*   将累加器中的值存储到变量和上下文中。
*   执行全局变量的加载和存储。
*   执行属性的加载和存储（包括普通属性和带索引的属性）。
*   执行各种算术和位运算。
*   进行类型转换。
*   实现逻辑运算。
*   调用函数和构造函数。
*   进行比较操作。

**与 JavaScript 的关系以及 JavaScript 示例：**

这个文件是 V8 引擎解释器实现的核心部分，直接负责执行 JavaScript 代码的底层操作。每个字节码指令都对应着 JavaScript 中的某个操作或语法结构。

以下是一些这个文件中定义的 handler 对应的 JavaScript 示例：

*   **`LdaZero`**:  对应 JavaScript 字面量 `0`。
    ```javascript
    let x = 0;
    ```
*   **`LdaSmi`**: 对应 JavaScript 中的小整数。
    ```javascript
    let y = 10;
    ```
*   **`LdaConstant`**: 对应 JavaScript 中的常量，例如字符串、布尔值等。
    ```javascript
    const message = "hello";
    const flag = true;
    ```
*   **`Ldar` 和 `Star`**: 对应 JavaScript 中的变量赋值。
    ```javascript
    let a = 5;
    let b = a; // 'Ldar' 加载 a 的值，'Star' 存储到 b
    ```
*   **`Add`**: 对应 JavaScript 中的加法运算符 `+`。
    ```javascript
    let sum = 5 + 3;
    ```
*   **`GetNamedProperty`**: 对应 JavaScript 中访问对象的属性。
    ```javascript
    const obj = { name: "Alice" };
    let personName = obj.name;
    ```
*   **`SetNamedProperty`**: 对应 JavaScript 中设置对象的属性。
    ```javascript
    const data = {};
    data.value = 100;
    ```
*   **`CallProperty`**: 对应 JavaScript 中调用对象的方法。
    ```javascript
    const myObj = {
      greet: function() { console.log("Hello!"); }
    };
    myObj.greet();
    ```
*   **`LdaGlobal` 和 `StaGlobal`**: 对应 JavaScript 中访问和修改全局变量。
    ```javascript
    globalVar = 20; // StaGlobal
    console.log(globalVar); // LdaGlobal
    ```
*   **`LdaContextSlot` 和 `StaContextSlot`**: 对应 JavaScript 中访问和修改闭包中的变量。
    ```javascript
    function outer() {
      let outerVar = 10;
      function inner() {
        console.log(outerVar); // LdaContextSlot
        outerVar = 20;        // StaContextSlot
      }
      inner();
    }
    outer();
    ```

总而言之，`v8/src/interpreter/interpreter-generator.cc` (第一部分) 负责生成解释器执行 JavaScript 代码所需的关键代码片段，将高级的 JavaScript 语法结构转换为底层的机器指令序列。这个文件中的每一个 handler 都是连接 JavaScript 代码和 V8 引擎底层实现的桥梁。

Prompt: 
```
这是目录为v8/src/interpreter/interpreter-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

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
      CAST(LoadContextElement(module_context, Context::EXTENSION_INDEX));

  Label if_export(this), if_import(this), end(this);
  Branch(IntPtrGreaterThan(cell_index, IntPtrConstant(0)), &if_export,
         &if_import);

  BIND(&if_export);
  {
    TNode<FixedArray> regular_exports = LoadObjectField<FixedArray>(
        module, SourceTextModule::kRegularExportsOffset);
    // The actual array index is (cell_index - 1).
    TNode<IntPtrT> export_index = IntPtrSub(cell_index, IntPtrConstant(1));
    TNode<Cell> cell =
        CAST(LoadFixedArrayElement(regular_exports, export_index));
    SetAccumulator(LoadObjectField(cell, Cell::kValueOffset));
    Goto(&end);
  }

  BIND(&if_import);
  {
    TNode<FixedArray> regular_imports = LoadObjectField<FixedArray>(
        module, SourceTextModule::kRegularImportsOffset);
    // The actual array index is (-cell_index - 1).
    TNode<IntPtrT> import_index = IntPtrSub(IntPtrConstant(-1), cell_index);
    TNode<Cell> cell =
        CAST(LoadFixedArrayElement(regular_imports, import_index));
    SetAccumulator(LoadObjectField(cell, Cell::kValueOffset));
    Goto(&end);
  }

  BIND(&end);
  Dispatch();
}

// StaModuleVariable <cell_index> <depth>
//
// Store accumulator to the module variable identified by <cell_index>.
// <depth> is the depth of the current context relative to the module context.
IGNITION_HANDLER(StaModuleVariable, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<IntPtrT> cell_index = BytecodeOperandImmIntPtr(0);
  TNode<Uint32T> depth = BytecodeOperandUImm(1);

  TNode<Context> module_context = GetContextAtDepth(GetContext(), depth);
  TNode<SourceTextModule> module =
      CAST(LoadContextElement(module_context, Context::EXTENSION_INDEX));

  Label if_export(this), if_import(this), end(this);
  Branch(IntPtrGreaterThan(cell_index, IntPtrConstant(0)), &if_export,
         &if_import);

  BIND(&if_export);
  {
    TNode<FixedArray> regular_exports = LoadObjectField<FixedArray>(
        module, SourceTextModule::kRegularExportsOffset);
    // The actual array index is (cell_index - 1).
    TNode<IntPtrT> export_index = IntPtrSub(cell_index, IntPtrConstant(1));
    TNode<HeapObject> cell =
        CAST(LoadFixedArrayElement(regular_exports, export_index));
    StoreObjectField(cell, Cell::kValueOffset, value);
    Goto(&end);
  }

  BIND(&if_import);
  {
    // Not supported (probably never).
    Abort(AbortReason::kUnsupportedModuleOperation);
    Goto(&end);
  }

  BIND(&end);
  Dispatch();
}

// PushContext <context>
//
// Saves the current context in <context>, and pushes the accumulator as the
// new current context.
IGNITION_HANDLER(PushContext, InterpreterAssembler) {
  TNode<Context> new_context = CAST(GetAccumulator());
  TNode<Context> old_context = GetContext();
  StoreRegisterAtOperandIndex(old_context, 0);
  SetContext(new_context);
  Dispatch();
}

// PopContext <context>
//
// Pops the current context and sets <context> as the new context.
IGNITION_HANDLER(PopContext, InterpreterAssembler) {
  TNode<Context> context = CAST(LoadRegisterAtOperandIndex(0));
  SetContext(context);
  Dispatch();
}

class InterpreterBinaryOpAssembler : public InterpreterAssembler {
 public:
  InterpreterBinaryOpAssembler(CodeAssemblerState* state, Bytecode bytecode,
                               OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  using BinaryOpGenerator = TNode<Object> (BinaryOpAssembler::*)(
      const LazyNode<Context>& context, TNode<Object> left, TNode<Object> right,
      TNode<UintPtrT> slot, const LazyNode<HeapObject>& maybe_feedback_vector,
      UpdateFeedbackMode update_feedback_mode, bool rhs_known_smi);

  void BinaryOpWithFeedback(BinaryOpGenerator generator) {
    TNode<Object> lhs = LoadRegisterAtOperandIndex(0);
    TNode<Object> rhs = GetAccumulator();
    TNode<Context> context = GetContext();
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = (binop_asm.*generator)(
        [=] { return context; }, lhs, rhs, slot_index,
        [=] { return maybe_feedback_vector; }, mode, false);
    SetAccumulator(result);
    Dispatch();
  }

  void BinaryOpSmiWithFeedback(BinaryOpGenerator generator) {
    TNode<Object> lhs = GetAccumulator();
    TNode<Smi> rhs = BytecodeOperandImmSmi(0);
    TNode<Context> context = GetContext();
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = (binop_asm.*generator)(
        [=] { return context; }, lhs, rhs, slot_index,
        [=] { return maybe_feedback_vector; }, mode, true);
    SetAccumulator(result);
    Dispatch();
  }
};

// Add <src>
//
// Add register <src> to accumulator.
IGNITION_HANDLER(Add, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_AddWithFeedback);
}

// Sub <src>
//
// Subtract register <src> from accumulator.
IGNITION_HANDLER(Sub, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_SubtractWithFeedback);
}

// Mul <src>
//
// Multiply accumulator by register <src>.
IGNITION_HANDLER(Mul, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_MultiplyWithFeedback);
}

// Div <src>
//
// Divide register <src> by accumulator.
IGNITION_HANDLER(Div, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_DivideWithFeedback);
}

// Mod <src>
//
// Modulo register <src> by accumulator.
IGNITION_HANDLER(Mod, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_ModulusWithFeedback);
}

// Exp <src>
//
// Exponentiate register <src> (base) with accumulator (exponent).
IGNITION_HANDLER(Exp, InterpreterBinaryOpAssembler) {
  BinaryOpWithFeedback(&BinaryOpAssembler::Generate_ExponentiateWithFeedback);
}

// AddSmi <imm>
//
// Adds an immediate value <imm> to the value in the accumulator.
IGNITION_HANDLER(AddSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_AddWithFeedback);
}

// SubSmi <imm>
//
// Subtracts an immediate value <imm> from the value in the accumulator.
IGNITION_HANDLER(SubSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_SubtractWithFeedback);
}

// MulSmi <imm>
//
// Multiplies an immediate value <imm> to the value in the accumulator.
IGNITION_HANDLER(MulSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_MultiplyWithFeedback);
}

// DivSmi <imm>
//
// Divides the value in the accumulator by immediate value <imm>.
IGNITION_HANDLER(DivSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_DivideWithFeedback);
}

// ModSmi <imm>
//
// Modulo accumulator by immediate value <imm>.
IGNITION_HANDLER(ModSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(&BinaryOpAssembler::Generate_ModulusWithFeedback);
}

// ExpSmi <imm>
//
// Exponentiate accumulator (base) with immediate value <imm> (exponent).
IGNITION_HANDLER(ExpSmi, InterpreterBinaryOpAssembler) {
  BinaryOpSmiWithFeedback(
      &BinaryOpAssembler::Generate_ExponentiateWithFeedback);
}

class InterpreterBitwiseBinaryOpAssembler : public InterpreterAssembler {
 public:
  InterpreterBitwiseBinaryOpAssembler(CodeAssemblerState* state,
                                      Bytecode bytecode,
                                      OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void BitwiseBinaryOpWithFeedback(Operation bitwise_op) {
    TNode<Object> left = LoadRegisterAtOperandIndex(0);
    TNode<Object> right = GetAccumulator();
    TNode<Context> context = GetContext();
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = binop_asm.Generate_BitwiseBinaryOpWithFeedback(
        bitwise_op, left, right, [=] { return context; }, slot_index,
        [=] { return maybe_feedback_vector; }, mode, false);

    SetAccumulator(result);
    Dispatch();
  }

  void BitwiseBinaryOpWithSmi(Operation bitwise_op) {
    TNode<Object> left = GetAccumulator();
    TNode<Smi> right = BytecodeOperandImmSmi(0);
    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<Context> context = GetContext();
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

    BinaryOpAssembler binop_asm(state());
    TNode<Object> result = binop_asm.Generate_BitwiseBinaryOpWithFeedback(
        bitwise_op, left, right, [=] { return context; }, slot_index,
        [=] { return maybe_feedback_vector; }, mode, true);

    SetAccumulator(result);
    Dispatch();
  }
};

// BitwiseOr <src>
//
// BitwiseOr register <src> to accumulator.
IGNITION_HANDLER(BitwiseOr, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kBitwiseOr);
}

// BitwiseXor <src>
//
// BitwiseXor register <src> to accumulator.
IGNITION_HANDLER(BitwiseXor, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kBitwiseXor);
}

// BitwiseAnd <src>
//
// BitwiseAnd register <src> to accumulator.
IGNITION_HANDLER(BitwiseAnd, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kBitwiseAnd);
}

// ShiftLeft <src>
//
// Left shifts register <src> by the count specified in the accumulator.
// Register <src> is converted to an int32 and the accumulator to uint32
// before the operation. 5 lsb bits from the accumulator are used as count
// i.e. <src> << (accumulator & 0x1F).
IGNITION_HANDLER(ShiftLeft, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kShiftLeft);
}

// ShiftRight <src>
//
// Right shifts register <src> by the count specified in the accumulator.
// Result is sign extended. Register <src> is converted to an int32 and the
// accumulator to uint32 before the operation. 5 lsb bits from the accumulator
// are used as count i.e. <src> >> (accumulator & 0x1F).
IGNITION_HANDLER(ShiftRight, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kShiftRight);
}

// ShiftRightLogical <src>
//
// Right Shifts register <src> by the count specified in the accumulator.
// Result is zero-filled. The accumulator and register <src> are converted to
// uint32 before the operation 5 lsb bits from the accumulator are used as
// count i.e. <src> << (accumulator & 0x1F).
IGNITION_HANDLER(ShiftRightLogical, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithFeedback(Operation::kShiftRightLogical);
}

// BitwiseOrSmi <imm>
//
// BitwiseOrSmi accumulator with <imm>.
IGNITION_HANDLER(BitwiseOrSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kBitwiseOr);
}

// BitwiseXorSmi <imm>
//
// BitwiseXorSmi accumulator with <imm>.
IGNITION_HANDLER(BitwiseXorSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kBitwiseXor);
}

// BitwiseAndSmi <imm>
//
// BitwiseAndSmi accumulator with <imm>.
IGNITION_HANDLER(BitwiseAndSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kBitwiseAnd);
}

#ifndef V8_ENABLE_EXPERIMENTAL_TSA_BUILTINS

// BitwiseNot <feedback_slot>
//
// Perform bitwise-not on the accumulator.
IGNITION_HANDLER(BitwiseNot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_BitwiseNotWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

#endif

// ShiftLeftSmi <imm>
//
// Left shifts accumulator by the count specified in <imm>.
// The accumulator is converted to an int32 before the operation. The 5
// lsb bits from <imm> are used as count i.e. <src> << (<imm> & 0x1F).
IGNITION_HANDLER(ShiftLeftSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kShiftLeft);
}

// ShiftRightSmi <imm>
//
// Right shifts accumulator by the count specified in <imm>. Result is sign
// extended. The accumulator is converted to an int32 before the operation. The
// 5 lsb bits from <imm> are used as count i.e. <src> >> (<imm> & 0x1F).
IGNITION_HANDLER(ShiftRightSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kShiftRight);
}

// ShiftRightLogicalSmi <imm>
//
// Right shifts accumulator by the count specified in <imm>. Result is zero
// extended. The accumulator is converted to an int32 before the operation. The
// 5 lsb bits from <imm> are used as count i.e. <src> >>> (<imm> & 0x1F).
IGNITION_HANDLER(ShiftRightLogicalSmi, InterpreterBitwiseBinaryOpAssembler) {
  BitwiseBinaryOpWithSmi(Operation::kShiftRightLogical);
}

// Negate <feedback_slot>
//
// Perform arithmetic negation on the accumulator.
IGNITION_HANDLER(Negate, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_NegateWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

// ToName <dst>
//
// Convert the object referenced by the accumulator to a name.
IGNITION_HANDLER(ToName, InterpreterAssembler) {
  TNode<Object> object = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result = CallBuiltin(Builtin::kToName, context, object);
  SetAccumulator(result);
  Dispatch();
}

// ToNumber <slot>
//
// Convert the object referenced by the accumulator to a number.
IGNITION_HANDLER(ToNumber, InterpreterAssembler) {
  ToNumberOrNumeric(Object::Conversion::kToNumber);
}

// ToNumeric <slot>
//
// Convert the object referenced by the accumulator to a numeric.
IGNITION_HANDLER(ToNumeric, InterpreterAssembler) {
  ToNumberOrNumeric(Object::Conversion::kToNumeric);
}

// ToObject <dst>
//
// Convert the object referenced by the accumulator to a JSReceiver.
IGNITION_HANDLER(ToObject, InterpreterAssembler) {
  TNode<Object> accumulator = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result = CallBuiltin(Builtin::kToObject, context, accumulator);
  StoreRegisterAtOperandIndex(result, 0);
  Dispatch();
}

// ToString
//
// Convert the accumulator to a String.
IGNITION_HANDLER(ToString, InterpreterAssembler) {
  SetAccumulator(ToString_Inline(GetContext(), GetAccumulator()));
  Dispatch();
}

// ToString
//
// Convert the accumulator to a String.
IGNITION_HANDLER(ToBoolean, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TVARIABLE(Boolean, result);
  Label if_true(this), if_false(this), end(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  {
    result = TrueConstant();
    Goto(&end);
  }
  BIND(&if_false);
  {
    result = FalseConstant();
    Goto(&end);
  }
  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// Inc
//
// Increments value in the accumulator by one.
IGNITION_HANDLER(Inc, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_IncrementWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

// Dec
//
// Decrements value in the accumulator by one.
IGNITION_HANDLER(Dec, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<UintPtrT> slot_index = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector =
      LoadFeedbackVectorOrUndefinedIfJitless();
  static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();

  UnaryOpAssembler unary_op_asm(state());
  TNode<Object> result = unary_op_asm.Generate_DecrementWithFeedback(
      context, value, slot_index, maybe_feedback_vector, mode);

  SetAccumulator(result);
  Dispatch();
}

// ToBooleanLogicalNot
//
// Perform logical-not on the accumulator, first casting the
// accumulator to a boolean value if required.
IGNITION_HANDLER(ToBooleanLogicalNot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TVARIABLE(Boolean, result);
  Label if_true(this), if_false(this), end(this);
  BranchIfToBooleanIsTrue(value, &if_true, &if_false);
  BIND(&if_true);
  {
    result = FalseConstant();
    Goto(&end);
  }
  BIND(&if_false);
  {
    result = TrueConstant();
    Goto(&end);
  }
  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// LogicalNot
//
// Perform logical-not on the accumulator, which must already be a boolean
// value.
IGNITION_HANDLER(LogicalNot, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TVARIABLE(Boolean, result);
  Label if_true(this), if_false(this), end(this);
  TNode<True> true_value = TrueConstant();
  TNode<False> false_value = FalseConstant();
  Branch(TaggedEqual(value, true_value), &if_true, &if_false);
  BIND(&if_true);
  {
    result = false_value;
    Goto(&end);
  }
  BIND(&if_false);
  {
    CSA_DCHECK(this, TaggedEqual(value, false_value));
    result = true_value;
    Goto(&end);
  }
  BIND(&end);
  SetAccumulator(result.value());
  Dispatch();
}

// TypeOf
//
// Load the accumulator with the string representating type of the
// object in the accumulator.
IGNITION_HANDLER(TypeOf, InterpreterAssembler) {
  TNode<Object> value = GetAccumulator();
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(0);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<String> result = Typeof(value, slot_id, maybe_feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

// DeletePropertyStrict
//
// Delete the property specified in the accumulator from the object
// referenced by the register operand following strict mode semantics.
IGNITION_HANDLER(DeletePropertyStrict, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> key = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallBuiltin(Builtin::kDeleteProperty, context, object, key,
                  SmiConstant(Smi::FromEnum(LanguageMode::kStrict)));
  SetAccumulator(result);
  Dispatch();
}

// DeletePropertySloppy
//
// Delete the property specified in the accumulator from the object
// referenced by the register operand following sloppy mode semantics.
IGNITION_HANDLER(DeletePropertySloppy, InterpreterAssembler) {
  TNode<Object> object = LoadRegisterAtOperandIndex(0);
  TNode<Object> key = GetAccumulator();
  TNode<Context> context = GetContext();
  TNode<Object> result =
      CallBuiltin(Builtin::kDeleteProperty, context, object, key,
                  SmiConstant(Smi::FromEnum(LanguageMode::kSloppy)));
  SetAccumulator(result);
  Dispatch();
}

// GetSuperConstructor
//
// Get the super constructor from the object referenced by the accumulator.
// The result is stored in register |reg|.
IGNITION_HANDLER(GetSuperConstructor, InterpreterAssembler) {
  TNode<JSFunction> active_function = CAST(GetAccumulator());
  TNode<Object> result = GetSuperConstructor(active_function);
  StoreRegisterAtOperandIndex(result, 0);
  Dispatch();
}

class InterpreterJSCallAssembler : public InterpreterAssembler {
 public:
  InterpreterJSCallAssembler(CodeAssemblerState* state, Bytecode bytecode,
                             OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  // Generates code to perform a JS call that collects type feedback.
  void JSCall(ConvertReceiverMode receiver_mode) {
    TNode<Object> function = LoadRegisterAtOperandIndex(0);
    RegListNodePair args = GetRegisterListAtOperandIndex(1);
    TNode<Context> context = GetContext();

#ifndef V8_JITLESS
    // Collect the {function} feedback.
    LazyNode<Object> receiver = [=, this] {
      return receiver_mode == ConvertReceiverMode::kNullOrUndefined
                 ? UndefinedConstant()
                 : LoadRegisterAtOperandIndex(1);
    };
    TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
    TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
    CollectCallFeedback(function, receiver, context, maybe_feedback_vector,
                        slot_id);
#endif  // !V8_JITLESS

    // Call the function and dispatch to the next handler.
    CallJSAndDispatch(function, context, args, receiver_mode);
  }

  // Generates code to perform a JS call with a known number of arguments that
  // collects type feedback.
  void JSCallN(int arg_count, ConvertReceiverMode receiver_mode) {
    // Indices and counts of operands on the bytecode.
    const int kFirstArgumentOperandIndex = 1;
    const int kReceiverOperandCount =
        (receiver_mode == ConvertReceiverMode::kNullOrUndefined) ? 0 : 1;
    const int kReceiverAndArgOperandCount = kReceiverOperandCount + arg_count;

    TNode<Object> function = LoadRegisterAtOperandIndex(0);
    TNode<Context> context = GetContext();

#ifndef V8_JITLESS
    // Collect the {function} feedback.
    LazyNode<Object> receiver = [=, this] {
      return receiver_mode == ConvertReceiverMode::kNullOrUndefined
                 ? UndefinedConstant()
                 : LoadRegisterAtOperandIndex(1);
    };
    const int kSlotOperandIndex =
        kFirstArgumentOperandIndex + kReceiverAndArgOperandCount;
    TNode<UintPtrT> slot_id = BytecodeOperandIdx(kSlotOperandIndex);
    TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
    CollectCallFeedback(function, receiver, context, maybe_feedback_vector,
                        slot_id);
#endif  // !V8_JITLESS

    switch (kReceiverAndArgOperandCount) {
      case 0:
        CallJSAndDispatch(function, context, Int32Constant(arg_count),
                          receiver_mode);
        break;
      case 1:
        CallJSAndDispatch(
            function, context, Int32Constant(arg_count), receiver_mode,
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex));
        break;
      case 2:
        CallJSAndDispatch(
            function, context, Int32Constant(arg_count), receiver_mode,
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex + 1),
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex));
        break;
      case 3:
        CallJSAndDispatch(
            function, context, Int32Constant(arg_count), receiver_mode,
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex + 2),
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex + 1),
            LoadRegisterAtOperandIndex(kFirstArgumentOperandIndex));
        break;
      default:
        UNREACHABLE();
    }
  }
};

// Call <callable> <receiver> <arg_count> <feedback_slot_id>
//
// Call a JSfunction or Callable in |callable| with the |receiver| and
// |arg_count| arguments in subsequent registers. Collect type feedback
// into |feedback_slot_id|
IGNITION_HANDLER(CallAnyReceiver, InterpreterJSCallAssembler) {
  JSCall(ConvertReceiverMode::kAny);
}

IGNITION_HANDLER(CallProperty, InterpreterJSCallAssembler) {
  JSCall(ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallProperty0, InterpreterJSCallAssembler) {
  JSCallN(0, ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallProperty1, InterpreterJSCallAssembler) {
  JSCallN(1, ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallProperty2, InterpreterJSCallAssembler) {
  JSCallN(2, ConvertReceiverMode::kNotNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver, InterpreterJSCallAssembler) {
  JSCall(ConvertReceiverMode::kNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver0, InterpreterJSCallAssembler) {
  JSCallN(0, ConvertReceiverMode::kNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver1, InterpreterJSCallAssembler) {
  JSCallN(1, ConvertReceiverMode::kNullOrUndefined);
}

IGNITION_HANDLER(CallUndefinedReceiver2, InterpreterJSCallAssembler) {
  JSCallN(2, ConvertReceiverMode::kNullOrUndefined);
}

// CallRuntime <function_id> <first_arg> <arg_count>
//
// Call the runtime function |function_id| with the first argument in
// register |first_arg| and |arg_count| arguments in subsequent
// registers.
IGNITION_HANDLER(CallRuntime, InterpreterAssembler) {
  TNode<Uint32T> function_id = BytecodeOperandRuntimeId(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<Context> context = GetContext();
  TNode<Object> result = CallRuntimeN(function_id, context, args, 1);
  SetAccumulator(result);
  Dispatch();
}

// InvokeIntrinsic <function_id> <first_arg> <arg_count>
//
// Implements the semantic equivalent of calling the runtime function
// |function_id| with the first argument in |first_arg| and |arg_count|
// arguments in subsequent registers.
IGNITION_HANDLER(InvokeIntrinsic, InterpreterAssembler) {
  TNode<Uint32T> function_id = BytecodeOperandIntrinsicId(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<Context> context = GetContext();
  TNode<Object> result =
      GenerateInvokeIntrinsic(this, function_id, context, args);
  SetAccumulator(result);
  Dispatch();
}

// CallRuntimeForPair <function_id> <first_arg> <arg_count> <first_return>
//
// Call the runtime function |function_id| which returns a pair, with the
// first argument in register |first_arg| and |arg_count| arguments in
// subsequent registers. Returns the result in <first_return> and
// <first_return + 1>
IGNITION_HANDLER(CallRuntimeForPair, InterpreterAssembler) {
  // Call the runtime function.
  TNode<Uint32T> function_id = BytecodeOperandRuntimeId(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<Context> context = GetContext();
  auto result_pair =
      CallRuntimeN<PairT<Object, Object>>(function_id, context, args, 2);
  // Store the results in <first_return> and <first_return + 1>
  TNode<Object> result0 = Projection<0>(result_pair);
  TNode<Object> result1 = Projection<1>(result_pair);
  StoreRegisterPairAtOperandIndex(result0, result1, 3);
  ClobberAccumulator(result0);
  Dispatch();
}

// CallJSRuntime <context_index> <receiver> <arg_count>
//
// Call the JS runtime function that has the |context_index| with the receiver
// in register |receiver| and |arg_count| arguments in subsequent registers.
IGNITION_HANDLER(CallJSRuntime, InterpreterAssembler) {
  TNode<IntPtrT> context_index = Signed(BytecodeOperandNativeContextIndex(0));
  RegListNodePair args = GetRegisterListAtOperandIndex(1);

  // Get the function to call from the native context.
  TNode<Context> context = GetContext();
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Object> function = LoadContextElement(native_context, context_index);

  // Call the function.
  CallJSAndDispatch(function, context, args,
                    ConvertReceiverMode::kNullOrUndefined);
}

// CallWithSpread <callable> <first_arg> <arg_count>
//
// Call a JSfunction or Callable in |callable| with the receiver in
// |first_arg| and |arg_count - 1| arguments in subsequent registers. The
// final argument is always a spread.
//
IGNITION_HANDLER(CallWithSpread, InterpreterAssembler) {
  TNode<Object> callable = LoadRegisterAtOperandIndex(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
  TNode<Context> context = GetContext();

  // Call into Runtime function CallWithSpread which does everything.
  CallJSWithSpreadAndDispatch(callable, context, args, slot_id);
}

// ConstructWithSpread <constructor> <first_arg> <arg_count>
//
// Call the constructor in |constructor| with the first argument in register
// |first_arg| and |arg_count| arguments in subsequent registers. The final
// argument is always a spread. The new.target is in the accumulator.
//
IGNITION_HANDLER(ConstructWithSpread, InterpreterAssembler) {
  TNode<Object> new_target = GetAccumulator();
  TNode<Object> constructor = LoadRegisterAtOperandIndex(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
  TNode<Context> context = GetContext();
  TNode<Object> result =
      ConstructWithSpread(constructor, context, new_target, args, slot_id);
  SetAccumulator(result);
  Dispatch();
}

// ConstructForwardAllArgs <constructor>
//
// Call the constructor in |constructor|, forwarding all arguments in the
// current frame. The new.target is in the accumulator.
//
IGNITION_HANDLER(ConstructForwardAllArgs, InterpreterAssembler) {
  TNode<Object> new_target = GetAccumulator();
  TNode<Object> constructor = LoadRegisterAtOperandIndex(0);
  TNode<TaggedIndex> slot_id = BytecodeOperandIdxTaggedIndex(1);
  TNode<Context> context = GetContext();
  TNode<Object> result =
      ConstructForwardAllArgs(constructor, context, new_target, slot_id);
  SetAccumulator(result);
  Dispatch();
}

// Construct <constructor> <first_arg> <arg_count>
//
// Call operator construct with |constructor| and the first argument in
// register |first_arg| and |arg_count| arguments in subsequent
// registers. The new.target is in the accumulator.
//
IGNITION_HANDLER(Construct, InterpreterAssembler) {
  TNode<Object> new_target = GetAccumulator();
  TNode<Object> constructor = LoadRegisterAtOperandIndex(0);
  RegListNodePair args = GetRegisterListAtOperandIndex(1);
  TNode<UintPtrT> slot_id = BytecodeOperandIdx(3);
  TNode<HeapObject> maybe_feedback_vector = LoadFeedbackVector();
  TNode<Context> context = GetContext();
  TNode<Object> result = Construct(constructor, context, new_target, args,
                                   slot_id, maybe_feedback_vector);
  SetAccumulator(result);
  Dispatch();
}

class InterpreterCompareOpAssembler : public InterpreterAssembler {
 public:
  InterpreterCompareOpAssembler(CodeAssemblerState* state, Bytecode bytecode,
                                OperandScale operand_scale)
      : InterpreterAssembler(state, bytecode, operand_scale) {}

  void CompareOpWithFeedback(Operation compare_op) {
    TNode<Object> lhs = LoadRegisterAtOperandIndex(0);
    TNode<Object> rhs = GetAccumulator();
    TNode<Context> context = GetContext();

    TVARIABLE(Smi, var_type_feedback);
    TVARIABLE(Object, var_exception);
    Label if_exception(this, Label::kDeferred);
    TNode<Boolean> result;
    {
      ScopedExceptionHandler handler(this, &if_exception, &var_exception);
      switch (compare_op) {
        case Operation::kEqual:
          result = Equal(lhs, rhs, context, &var_type_feedback);
          break;
        case Operation::kStrictEqual:
          result = StrictEqual(lhs, rhs, &var_type_feedback);
          break;
        case Operation::kLessThan:
        case Operation::kGreaterThan:
        case Operation::kLessThanOrEqual:
        case Operation::kGreaterThanOrEqual:
          result = RelationalComparison(compare_op, lhs, rhs, context,
                                        &var_type_feedback);
          break;
        default:
          UNREACHABLE();
      }
    }

    TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
    TNode<HeapObject> maybe_feedback_vector =
        LoadFeedbackVectorOrUndefinedIfJitless();
    static constexpr UpdateFeedbackMode mode = DefaultUpdateFeedbackMode();
    UpdateFeedback(var_type_feedback.value(), maybe_feedback_vector, slot_index,
                   mode);
    SetAccumulator(result);
    Dispatch();

    BIND(&if_exception);
    {
      TNode<UintPtrT> slot_index = BytecodeOperandIdx(1);
      TNode<HeapObject> maybe_feedback_
"""


```