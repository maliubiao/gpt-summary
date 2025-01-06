Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript examples.

1. **Understand the Goal:** The core request is to understand the functionality of `csa-generator.cc` within the V8/Torque context and connect it to JavaScript concepts.

2. **Initial Skim and Keywords:**  Quickly read through the code, looking for recognizable terms. "CSA," "CodeStubAssembler," "TNode," "Builtin," "Runtime," "Macro," "Block," "Instruction," "Emit," "Stack," "Type." These suggest a code generation process within V8's internal machinery. The `// Copyright 2018 the V8 project authors` clearly places it within the V8 project.

3. **Identify the Core Class:** The name `CSAGenerator` strongly suggests this class is responsible for generating something related to CSA.

4. **Analyze the `EmitGraph` Function:** This seems like the main entry point. It iterates through "blocks" (likely control flow blocks), sets up "labels" (`CodeAssemblerParameterizedLabel`), and calls `EmitInstruction`. This strongly hints at a compilation or code generation process where structured code is being transformed into lower-level instructions.

5. **Focus on `EmitInstruction` Overloads:** The numerous overloaded `EmitInstruction` functions are key. Each one handles a specific type of instruction (e.g., `PushUninitializedInstruction`, `CallIntrinsicInstruction`, `BranchInstruction`). This reveals that the generator processes instructions one by one.

6. **Connect "CSA" and "TNode":** The repeated use of `CodeStubAssembler` and `TNode` is significant. Recall that CSA is V8's assembly-like language for optimizing built-in functions. `TNode` likely represents a typed node in the CSA graph. This confirms the code is about generating CSA code.

7. **Look for JavaScript Connections:**  Keywords like "Builtin," "Runtime," and the example of `%RawDownCast` (a JavaScript-visible function) indicate the generated CSA code is related to implementing JavaScript features or optimizations.

8. **Understand the Flow within `EmitInstruction`:**  For various instruction types, the code manipulates a `Stack<std::string>`. The strings pushed onto the stack seem to represent CSA code snippets (e.g., `ca_.Uninitialized<...>`). This confirms the code *generates* CSA code as strings.

9. **Identify Key Concepts and Their Mapping:**
    * **Torque:** The high-level language.
    * **CSA:** The low-level assembly-like language.
    * **`CSAGenerator`:** The translator from Torque instructions to CSA code.
    * **Instructions (e.g., `CallIntrinsicInstruction`):** Operations in the Torque language.
    * **`EmitInstruction`:** The method that translates a Torque instruction into CSA code.
    * **`Stack<std::string>`:**  Used to build up the CSA code snippets.
    * **`TNode`:** Represents a typed value in the generated CSA code.
    * **Builtins, Runtimes, Macros:**  Different categories of functions or code blocks in V8, all eventually needing CSA representation.

10. **Formulate the High-Level Functionality:** Based on the above, the core functionality is to take a representation of Torque code (likely in the form of instructions and control flow graphs) and generate equivalent C++ code using V8's `CodeStubAssembler` API.

11. **Address the JavaScript Relationship:** The generated CSA code is used to implement or optimize JavaScript built-in functions (like `Array.prototype.push`, `Object.keys`). This is the crucial link between the C++ code and JavaScript.

12. **Craft JavaScript Examples:**  Choose common JavaScript operations and explain how they might relate to the generated CSA code.
    * **`Array.prototype.push`:**  A fundamental array operation. Likely has an optimized CSA implementation.
    * **`parseInt`:** A built-in function. Its implementation could involve CSA for performance.
    * **`Object.keys`:** Another built-in object method, a good candidate for CSA optimization.

13. **Connect the Examples to Specific Code:**  Point out how elements in the C++ code (e.g., `CallBuiltinInstruction`, `CallRuntimeInstruction`) would be involved in implementing these JavaScript features. Emphasize that the generated CSA code directly manipulates V8's internal objects and data structures.

14. **Refine and Organize:** Structure the answer logically, starting with a concise summary, then elaborating on the details, and finally providing concrete JavaScript examples. Use clear and precise language. Highlight the connection to V8's optimization strategy.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just about generating C++ *declarations*. However, the presence of control flow (`GotoInstruction`, `BranchInstruction`) and calls to builtins and runtimes suggests it's more than just declarations. It's generating the *implementation* logic.
* **Realization:**  The `Stack<std::string>` isn't just storing values; it's accumulating CSA *code strings*. This is a key insight.
* **Clarity:** Ensure the distinction between Torque (the input), `CSAGenerator` (the translator), and CSA (the output) is clear. Avoid jargon where possible or explain it concisely.
* **JavaScript Relevance:** Make the connection to JavaScript as explicit as possible. Don't just say "it's related"; explain *how* it's related.

By following this iterative process of skimming, analyzing key functions, connecting concepts, and generating examples, we arrive at a comprehensive understanding of the `csa-generator.cc` file and its role in the V8 JavaScript engine.
这个C++源代码文件 `csa-generator.cc` 的主要功能是 **将 Torque 中间表示（IR）转换为 CodeStubAssembler (CSA) 代码**。

简单来说，Torque 是一种用于编写 V8 内部（如内置函数、运行时函数）的高级领域特定语言，而 CSA 是 V8 中用于生成高效机器码的低级汇编器风格的 API。`csa-generator.cc` 的作用就像一个编译器，将 Torque 代码“翻译”成可以在 V8 中执行的 CSA 代码。

以下是更详细的功能归纳：

1. **接收 Torque 的控制流图 (CFG):**  `CSAGenerator::EmitGraph` 函数是入口点，它接收由 Torque 编译器生成的控制流图。这个图包含了代码的基本块和它们之间的控制流关系。

2. **为每个基本块生成 CSA 标签:**  代码遍历 CFG 中的每个基本块，并为其生成一个对应的 CSA 标签 (`compiler::CodeAssemblerParameterizedLabel`). 这些标签用于在生成的 CSA 代码中跳转。

3. **遍历基本块并生成 CSA 指令:** `EmitBlock` 函数负责处理单个基本块，并遍历其中的每条 Torque 指令。对于每条指令，会调用相应的 `EmitInstruction` 重载函数。

4. **将 Torque 指令转换为 CSA 代码:**  `EmitInstruction` 的多个重载函数是这个文件的核心。每个重载函数负责处理一种特定的 Torque 指令，并将其转换为等价的 CSA 代码。例如：
    * `EmitInstruction(const PushUninitializedInstruction&...)`: 生成 CSA 代码来创建一个未初始化的 TNode。
    * `EmitInstruction(const CallIntrinsicInstruction&...)`: 生成 CSA 代码来调用一个内部函数（intrinsic）。
    * `EmitInstruction(const CallCsaMacroInstruction&...)`: 生成 CSA 代码来调用另一个用 Torque 编写的宏。
    * `EmitInstruction(const BranchInstruction&...)`: 生成 CSA 代码来实现条件分支。
    * `EmitInstruction(const ReturnInstruction&...)`: 生成 CSA 代码来返回。

5. **管理 CSA 代码生成的状态:**  `CSAGenerator` 类维护了一些状态，例如当前的代码输出流 (`out()`)、声明输出流 (`decls()`)、以及用于跟踪变量定义的映射。

6. **处理异常:** 代码中包含对异常处理的支持，例如 `PreCallableExceptionPreparation` 和 `PostCallableExceptionPreparation` 函数，用于生成 CSA 代码来处理可能抛出的异常。

7. **支持不同的数据类型:** 代码能够处理 Torque 中的各种数据类型，并生成相应的 CSA 代码来操作这些类型，例如使用 `TNode<>` 来表示堆对象。

**它与 JavaScript 的功能的关系，并用 JavaScript 举例说明:**

`csa-generator.cc` 生成的 CSA 代码直接用于实现 JavaScript 的内置功能和运行时行为。当 JavaScript 引擎需要执行一个内置函数（例如 `Array.prototype.push`、`parseInt` 等）或者执行一些底层的运行时操作时，它会执行由 Torque 编译并由 `csa-generator.cc` 生成的 CSA 代码。

**JavaScript 例子:**

假设 Torque 中有一个宏或内置函数实现了 JavaScript 的 `Array.prototype.push` 方法的一部分逻辑。`csa-generator.cc` 会将这个 Torque 代码转换为 CSA 代码，大致如下（这是一个简化的例子，实际生成的 CSA 代码会更复杂）：

```c++
void CSAGenerator::EmitInstruction(const CallBuiltinInstruction& instruction, Stack<std::string>* stack) {
  // ... 其他代码 ...
  if (instruction.builtin->ExternalName() == "ArrayPush") { // 假设内置函数名为 ArrayPush
    std::vector<std::string> arguments = stack->PopMany(instruction.argc);
    out() << "    // 调用 CSA 的方法来操作数组并添加元素\n";
    out() << "    TNode<JSArray> array = ca_.UncheckedCast<JSArray>(" << arguments[0] << ");\n";
    out() << "    TNode<Object> element = " << arguments[1] << ";\n";
    out() << "    TNode<Smi> initial_length = ca_.LoadFastJSArrayLength(array);\n";
    out() << "    // ... 更多 CSA 代码来执行 push 操作 ...\n";
    out() << "    ca_.StoreFastJSArrayLength(array, ...);\n";
    out() << "    CodeStubAssembler(state_).Return(initial_length);\n";
  }
  // ... 其他内置函数的处理 ...
}
```

当 JavaScript 代码执行 `[1, 2, 3].push(4)` 时，V8 引擎最终会执行与 `ArrayPush` 这个内置函数对应的 CSA 代码。这个 CSA 代码正是由 `csa-generator.cc` 根据 Torque 的定义生成的。

**更具体的 JavaScript 例子:**

1. **`Array.prototype.push()`:** 当你调用 `[1, 2].push(3)` 时，V8 内部会调用一个用 Torque 编写的、与 `Array.prototype.push` 相关的内置函数。`csa-generator.cc` 会生成 CSA 代码来执行以下操作：
    * 加载数组的长度。
    * 检查是否有足够的空间，可能需要调整数组大小。
    * 将新元素添加到数组的末尾。
    * 更新数组的长度。
    * 返回新的长度。

2. **`parseInt()`:**  `parseInt()` 函数的某些优化路径可能也由 Torque 和 CSA 实现。`csa-generator.cc` 会生成 CSA 代码来执行诸如：
    * 检查输入是否是字符串。
    * 跳过前导空格。
    * 确定基数（如果未指定）。
    * 将字符串转换为数字。
    * 处理错误情况。

3. **`Object.keys()`:** 获取对象的所有键的操作也可能通过 Torque 和 CSA 进行优化。`csa-generator.cc` 生成的 CSA 代码可能包括：
    * 获取对象的属性。
    * 过滤掉原型链上的属性（如果需要）。
    * 将键收集到一个数组中。
    * 返回包含键的数组。

**总结:**

`csa-generator.cc` 是 V8 编译流程中的一个关键组件，它负责将高级的 Torque 代码转换为可以在 V8 中高效执行的低级 CSA 代码。这种转换使得 V8 能够使用优化的机器码来实现 JavaScript 的各种内置功能和运行时操作，从而提高 JavaScript 的执行效率。 你编写的 JavaScript 代码最终会间接地依赖于 `csa-generator.cc` 生成的代码来运行。

Prompt: 
```
这是目录为v8/src/torque/csa-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/csa-generator.h"

#include <optional>

#include "src/common/globals.h"
#include "src/torque/global-context.h"
#include "src/torque/type-oracle.h"
#include "src/torque/types.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

std::optional<Stack<std::string>> CSAGenerator::EmitGraph(
    Stack<std::string> parameters) {
  for (BottomOffset i = {0}; i < parameters.AboveTop(); ++i) {
    SetDefinitionVariable(DefinitionLocation::Parameter(i.offset),
                          parameters.Peek(i));
  }

  for (Block* block : cfg_.blocks()) {
    if (block->IsDead()) continue;

    out() << "  compiler::CodeAssemblerParameterizedLabel<";
    bool first = true;
    DCHECK_EQ(block->InputTypes().Size(), block->InputDefinitions().Size());
    for (BottomOffset i = {0}; i < block->InputTypes().AboveTop(); ++i) {
      if (block->InputDefinitions().Peek(i).IsPhiFromBlock(block)) {
        if (!first) out() << ", ";
        out() << block->InputTypes().Peek(i)->GetGeneratedTNodeTypeName();
        first = false;
      }
    }
    out() << "> " << BlockName(block) << "(&ca_, compiler::CodeAssemblerLabel::"
          << (block->IsDeferred() ? "kDeferred" : "kNonDeferred") << ");\n";
  }

  EmitInstruction(GotoInstruction{cfg_.start()}, &parameters);
  for (Block* block : cfg_.blocks()) {
    if (cfg_.end() && *cfg_.end() == block) continue;
    if (block->IsDead()) continue;
    out() << "\n";

    // Redirect the output of non-declarations into a buffer and only output
    // declarations right away.
    std::stringstream out_buffer;
    std::ostream* old_out = out_;
    out_ = &out_buffer;

    out() << "  if (" << BlockName(block) << ".is_used()) {\n";
    EmitBlock(block);
    out() << "  }\n";

    // All declarations have been printed now, so we can append the buffered
    // output and redirect back to the original output stream.
    out_ = old_out;
    out() << out_buffer.str();
  }
  if (cfg_.end()) {
    out() << "\n";
    return EmitBlock(*cfg_.end());
  }
  return std::nullopt;
}

Stack<std::string> CSAGenerator::EmitBlock(const Block* block) {
  Stack<std::string> stack;
  std::stringstream phi_names;

  for (BottomOffset i = {0}; i < block->InputTypes().AboveTop(); ++i) {
    const auto& def = block->InputDefinitions().Peek(i);
    stack.Push(DefinitionToVariable(def));
    if (def.IsPhiFromBlock(block)) {
      decls() << "  TNode<"
              << block->InputTypes().Peek(i)->GetGeneratedTNodeTypeName()
              << "> " << stack.Top() << ";\n";
      phi_names << ", &" << stack.Top();
    }
  }
  out() << "    ca_.Bind(&" << BlockName(block) << phi_names.str() << ");\n";

  for (const Instruction& instruction : block->instructions()) {
    TorqueCodeGenerator::EmitInstruction(instruction, &stack);
  }
  return stack;
}

void CSAGenerator::EmitSourcePosition(SourcePosition pos, bool always_emit) {
  const std::string& file = SourceFileMap::AbsolutePath(pos.source);
  if (always_emit || !previous_position_.CompareStartIgnoreColumn(pos)) {
    // Lines in Torque SourcePositions are zero-based, while the
    // CodeStubAssembler and downwind systems are one-based.
    out() << "    ca_.SetSourcePosition(\"" << file << "\", "
          << (pos.start.line + 1) << ");\n";
    previous_position_ = pos;
  }
}

void CSAGenerator::EmitInstruction(
    const PushUninitializedInstruction& instruction,
    Stack<std::string>* stack) {
  // TODO(turbofan): This can trigger an error in CSA if it is used. Instead, we
  // should prevent usage of uninitialized in the type system. This
  // requires "if constexpr" being evaluated at Torque time.
  const std::string str = "ca_.Uninitialized<" +
                          instruction.type->GetGeneratedTNodeTypeName() + ">()";
  stack->Push(str);
  SetDefinitionVariable(instruction.GetValueDefinition(), str);
}

void CSAGenerator::EmitInstruction(
    const PushBuiltinPointerInstruction& instruction,
    Stack<std::string>* stack) {
  const std::string str =
      "ca_.UncheckedCast<BuiltinPtr>(ca_.SmiConstant(Builtin::k" +
      instruction.external_name + "))";
  stack->Push(str);
  SetDefinitionVariable(instruction.GetValueDefinition(), str);
}

void CSAGenerator::EmitInstruction(
    const NamespaceConstantInstruction& instruction,
    Stack<std::string>* stack) {
  const Type* type = instruction.constant->type();
  std::vector<std::string> results;

  const auto lowered = LowerType(type);
  for (std::size_t i = 0; i < lowered.size(); ++i) {
    results.push_back(DefinitionToVariable(instruction.GetValueDefinition(i)));
    stack->Push(results.back());
    decls() << "  TNode<" << lowered[i]->GetGeneratedTNodeTypeName() << "> "
            << stack->Top() << ";\n";
  }

  out() << "    ";
  if (type->StructSupertype()) {
    out() << "std::tie(";
    PrintCommaSeparatedList(out(), results);
    out() << ") = ";
  } else if (results.size() == 1) {
    out() << results[0] << " = ";
  }
  out() << instruction.constant->external_name() << "(state_)";
  if (type->StructSupertype()) {
    out() << ".Flatten();\n";
  } else {
    out() << ";\n";
  }
}

std::vector<std::string> CSAGenerator::ProcessArgumentsCommon(
    const TypeVector& parameter_types,
    std::vector<std::string> constexpr_arguments, Stack<std::string>* stack) {
  std::vector<std::string> args;
  for (auto it = parameter_types.rbegin(); it != parameter_types.rend(); ++it) {
    const Type* type = *it;
    if (type->IsConstexpr()) {
      args.push_back(std::move(constexpr_arguments.back()));
      constexpr_arguments.pop_back();
    } else {
      std::stringstream s;
      size_t slot_count = LoweredSlotCount(type);
      VisitResult arg = VisitResult(type, stack->TopRange(slot_count));
      EmitCSAValue(arg, *stack, s);
      args.push_back(s.str());
      stack->PopMany(slot_count);
    }
  }
  std::reverse(args.begin(), args.end());
  return args;
}

void CSAGenerator::EmitInstruction(const CallIntrinsicInstruction& instruction,
                                   Stack<std::string>* stack) {
  TypeVector parameter_types =
      instruction.intrinsic->signature().parameter_types.types;
  std::vector<std::string> args = ProcessArgumentsCommon(
      parameter_types, instruction.constexpr_arguments, stack);

  Stack<std::string> pre_call_stack = *stack;
  const Type* return_type = instruction.intrinsic->signature().return_type;
  std::vector<std::string> results;

  const auto lowered = LowerType(return_type);
  for (std::size_t i = 0; i < lowered.size(); ++i) {
    results.push_back(DefinitionToVariable(instruction.GetValueDefinition(i)));
    stack->Push(results.back());
    decls() << "  TNode<" << lowered[i]->GetGeneratedTNodeTypeName() << "> "
            << stack->Top() << ";\n";
  }

  out() << "    ";
  if (return_type->StructSupertype()) {
    out() << "std::tie(";
    PrintCommaSeparatedList(out(), results);
    out() << ") = ";
  } else {
    if (results.size() == 1) {
      out() << results[0] << " = ";
    }
  }

  if (instruction.intrinsic->ExternalName() == "%RawDownCast") {
    if (parameter_types.size() != 1) {
      ReportError("%RawDownCast must take a single parameter");
    }
    const Type* original_type = parameter_types[0];
    bool is_subtype =
        return_type->IsSubtypeOf(original_type) ||
        (original_type == TypeOracle::GetUninitializedHeapObjectType() &&
         return_type->IsSubtypeOf(TypeOracle::GetHeapObjectType()));
    if (!is_subtype) {
      ReportError("%RawDownCast error: ", *return_type, " is not a subtype of ",
                  *original_type);
    }
    if (!original_type->StructSupertype() &&
        return_type->GetGeneratedTNodeTypeName() !=
            original_type->GetGeneratedTNodeTypeName()) {
      if (return_type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
        out() << "TORQUE_CAST";
      } else {
        out() << "ca_.UncheckedCast<"
              << return_type->GetGeneratedTNodeTypeName() << ">";
      }
    }
  } else if (instruction.intrinsic->ExternalName() == "%GetClassMapConstant") {
    if (!parameter_types.empty()) {
      ReportError("%GetClassMapConstant must not take parameters");
    }
    if (instruction.specialization_types.size() != 1) {
      ReportError(
          "%GetClassMapConstant must take a single class as specialization "
          "parameter");
    }
    const ClassType* class_type =
        ClassType::DynamicCast(instruction.specialization_types[0]);
    if (!class_type) {
      ReportError("%GetClassMapConstant must take a class type parameter");
    }
    // If the class isn't actually used as the parameter to a TNode,
    // then we can't rely on the class existing in C++ or being of the same
    // type (e.g. it could be a template), so don't use the template CSA
    // machinery for accessing the class' map.
    std::string class_name =
        class_type->name() != class_type->GetGeneratedTNodeTypeName()
            ? std::string("void")
            : class_type->name();

    out() << std::string("CodeStubAssembler(state_).GetClassMapConstant<") +
                 class_name + ">";
  } else if (instruction.intrinsic->ExternalName() == "%FromConstexpr") {
    if (parameter_types.size() != 1 || !parameter_types[0]->IsConstexpr()) {
      ReportError(
          "%FromConstexpr must take a single parameter with constexpr "
          "type");
    }
    if (return_type->IsConstexpr()) {
      ReportError("%FromConstexpr must return a non-constexpr type");
    }
    if (return_type->IsSubtypeOf(TypeOracle::GetSmiType())) {
      out() << "ca_.SmiConstant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetNumberType())) {
      out() << "ca_.NumberConstant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetStringType())) {
      out() << "ca_.StringConstant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetObjectType())) {
      ReportError(
          "%FromConstexpr cannot cast to subclass of HeapObject unless it's a "
          "String or Number");
    } else if (return_type->IsSubtypeOf(TypeOracle::GetIntPtrType())) {
      out() << "ca_.IntPtrConstant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetUIntPtrType())) {
      out() << "ca_.UintPtrConstant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetInt32Type())) {
      out() << "ca_.Int32Constant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetUint8Type())) {
      out() << "TNode<Uint8T>::UncheckedCast(ca_.Uint32Constant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetUint32Type())) {
      out() << "ca_.Uint32Constant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetInt64Type())) {
      out() << "ca_.Int64Constant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetUint64Type())) {
      out() << "ca_.Uint64Constant";
    } else if (return_type->IsSubtypeOf(TypeOracle::GetBoolType())) {
      out() << "ca_.BoolConstant";
    } else {
      std::stringstream s;
      s << "%FromConstexpr does not support return type " << *return_type;
      ReportError(s.str());
    }
    // Wrap the raw constexpr value in a static_cast to ensure that
    // enums get properly casted to their backing integral value.
    out() << "(CastToUnderlyingTypeIfEnum";
  } else {
    ReportError("no built in intrinsic with name " +
                instruction.intrinsic->ExternalName());
  }

  out() << "(";
  PrintCommaSeparatedList(out(), args);
  if (instruction.intrinsic->ExternalName() == "%FromConstexpr") {
    out() << ")";
    if (return_type->IsSubtypeOf(TypeOracle::GetUint8Type())) {
      out() << ")";
    }
  }
  if (return_type->StructSupertype()) {
    out() << ").Flatten();\n";
  } else {
    out() << ");\n";
  }
}

void CSAGenerator::EmitInstruction(const CallCsaMacroInstruction& instruction,
                                   Stack<std::string>* stack) {
  TypeVector parameter_types =
      instruction.macro->signature().parameter_types.types;
  std::vector<std::string> args = ProcessArgumentsCommon(
      parameter_types, instruction.constexpr_arguments, stack);

  Stack<std::string> pre_call_stack = *stack;
  const Type* return_type = instruction.macro->signature().return_type;
  std::vector<std::string> results;

  const auto lowered = LowerType(return_type);
  for (std::size_t i = 0; i < lowered.size(); ++i) {
    results.push_back(DefinitionToVariable(instruction.GetValueDefinition(i)));
    stack->Push(results.back());
    decls() << "  TNode<" << lowered[i]->GetGeneratedTNodeTypeName() << "> "
            << stack->Top() << ";\n";
  }

  std::string catch_name =
      PreCallableExceptionPreparation(instruction.catch_block);
  out() << "    ";
  bool needs_flattening = return_type->StructSupertype().has_value();
  if (needs_flattening) {
    out() << "std::tie(";
    PrintCommaSeparatedList(out(), results);
    out() << ") = ";
  } else {
    if (results.size() == 1) {
      out() << results[0] << " = ";
    } else {
      DCHECK_EQ(0, results.size());
    }
  }
  if (ExternMacro* extern_macro = ExternMacro::DynamicCast(instruction.macro)) {
    out() << extern_macro->external_assembler_name() << "(state_).";
  } else {
    args.insert(args.begin(), "state_");
  }
  out() << instruction.macro->ExternalName() << "(";
  PrintCommaSeparatedList(out(), args);
  if (needs_flattening) {
    out() << ").Flatten();\n";
  } else {
    out() << ");\n";
  }
  PostCallableExceptionPreparation(catch_name, return_type,
                                   instruction.catch_block, &pre_call_stack,
                                   instruction.GetExceptionObjectDefinition());
}

void CSAGenerator::EmitInstruction(
    const CallCsaMacroAndBranchInstruction& instruction,
    Stack<std::string>* stack) {
  TypeVector parameter_types =
      instruction.macro->signature().parameter_types.types;
  std::vector<std::string> args = ProcessArgumentsCommon(
      parameter_types, instruction.constexpr_arguments, stack);

  Stack<std::string> pre_call_stack = *stack;
  std::vector<std::string> results;
  const Type* return_type = instruction.macro->signature().return_type;

  if (return_type != TypeOracle::GetNeverType()) {
    const auto lowered = LowerType(return_type);
    for (std::size_t i = 0; i < lowered.size(); ++i) {
      results.push_back(
          DefinitionToVariable(instruction.GetValueDefinition(i)));
      decls() << "  TNode<" << lowered[i]->GetGeneratedTNodeTypeName() << "> "
              << results.back() << ";\n";
    }
  }

  std::vector<std::string> label_names;
  std::vector<std::vector<std::string>> var_names;
  const LabelDeclarationVector& labels = instruction.macro->signature().labels;
  DCHECK_EQ(labels.size(), instruction.label_blocks.size());
  for (size_t i = 0; i < labels.size(); ++i) {
    TypeVector label_parameters = labels[i].types;
    label_names.push_back(FreshLabelName());
    var_names.push_back({});
    for (size_t j = 0; j < label_parameters.size(); ++j) {
      var_names[i].push_back(FreshNodeName());
      const auto def = instruction.GetLabelValueDefinition(i, j);
      SetDefinitionVariable(def, var_names[i].back() + ".value()");
      decls() << "    compiler::TypedCodeAssemblerVariable<"
              << label_parameters[j]->GetGeneratedTNodeTypeName() << "> "
              << var_names[i][j] << "(&ca_);\n";
    }
    out() << "    compiler::CodeAssemblerLabel " << label_names[i]
          << "(&ca_);\n";
  }

  std::string catch_name =
      PreCallableExceptionPreparation(instruction.catch_block);
  out() << "    ";
  if (results.size() == 1) {
    out() << results[0] << " = ";
  } else if (results.size() > 1) {
    out() << "std::tie(";
    PrintCommaSeparatedList(out(), results);
    out() << ") = ";
  }
  if (ExternMacro* extern_macro = ExternMacro::DynamicCast(instruction.macro)) {
    out() << extern_macro->external_assembler_name() << "(state_).";
  } else {
    args.insert(args.begin(), "state_");
  }
  out() << instruction.macro->ExternalName() << "(";
  PrintCommaSeparatedList(out(), args);
  bool first = args.empty();
  for (size_t i = 0; i < label_names.size(); ++i) {
    if (!first) out() << ", ";
    out() << "&" << label_names[i];
    first = false;
    for (size_t j = 0; j < var_names[i].size(); ++j) {
      out() << ", &" << var_names[i][j];
    }
  }
  if (return_type->StructSupertype()) {
    out() << ").Flatten();\n";
  } else {
    out() << ");\n";
  }

  PostCallableExceptionPreparation(catch_name, return_type,
                                   instruction.catch_block, &pre_call_stack,
                                   instruction.GetExceptionObjectDefinition());

  if (instruction.return_continuation) {
    out() << "    ca_.Goto(&" << BlockName(*instruction.return_continuation);
    DCHECK_EQ(stack->Size() + results.size(),
              (*instruction.return_continuation)->InputDefinitions().Size());

    const auto& input_definitions =
        (*instruction.return_continuation)->InputDefinitions();
    for (BottomOffset i = {0}; i < input_definitions.AboveTop(); ++i) {
      if (input_definitions.Peek(i).IsPhiFromBlock(
              *instruction.return_continuation)) {
        out() << ", "
              << (i < stack->AboveTop() ? stack->Peek(i) : results[i.offset]);
      }
    }
    out() << ");\n";
  }
  for (size_t l = 0; l < label_names.size(); ++l) {
    out() << "    if (" << label_names[l] << ".is_used()) {\n";
    out() << "      ca_.Bind(&" << label_names[l] << ");\n";
    out() << "      ca_.Goto(&" << BlockName(instruction.label_blocks[l]);
    DCHECK_EQ(stack->Size() + var_names[l].size(),
              instruction.label_blocks[l]->InputDefinitions().Size());

    const auto& label_definitions =
        instruction.label_blocks[l]->InputDefinitions();

    BottomOffset i = {0};
    for (; i < stack->AboveTop(); ++i) {
      if (label_definitions.Peek(i).IsPhiFromBlock(
              instruction.label_blocks[l])) {
        out() << ", " << stack->Peek(i);
      }
    }
    for (std::size_t k = 0; k < var_names[l].size(); ++k, ++i) {
      if (label_definitions.Peek(i).IsPhiFromBlock(
              instruction.label_blocks[l])) {
        out() << ", " << var_names[l][k] << ".value()";
      }
    }
    out() << ");\n";
    out() << "    }\n";
  }
}

void CSAGenerator::EmitInstruction(const MakeLazyNodeInstruction& instruction,
                                   Stack<std::string>* stack) {
  TypeVector parameter_types =
      instruction.macro->signature().parameter_types.types;
  std::vector<std::string> args = ProcessArgumentsCommon(
      parameter_types, instruction.constexpr_arguments, stack);

  std::string result_name =
      DefinitionToVariable(instruction.GetValueDefinition());

  stack->Push(result_name);

  decls() << "  " << instruction.result_type->GetGeneratedTypeName() << " "
          << result_name << ";\n";

  // We assume here that the CodeAssemblerState will outlive any usage of
  // the generated std::function that binds it. Likewise, copies of TNode values
  // are only valid during generation of the current builtin.
  out() << "    " << result_name << " = [=] () { return ";
  bool first = true;
  if (const ExternMacro* extern_macro =
          ExternMacro::DynamicCast(instruction.macro)) {
    out() << extern_macro->external_assembler_name() << "(state_)."
          << extern_macro->ExternalName() << "(";
  } else {
    out() << instruction.macro->ExternalName() << "(state_";
    first = false;
  }
  if (!args.empty()) {
    if (!first) out() << ", ";
    PrintCommaSeparatedList(out(), args);
  }
  out() << "); };\n";
}

void CSAGenerator::EmitInstruction(const CallBuiltinInstruction& instruction,
                                   Stack<std::string>* stack) {
  std::vector<std::string> arguments = stack->PopMany(instruction.argc);
  std::vector<const Type*> result_types =
      LowerType(instruction.builtin->signature().return_type);
  if (instruction.is_tailcall) {
    if (instruction.builtin->IsJavaScript()) {
      out() << "   CodeStubAssembler(state_).TailCallJSBuiltin(Builtin::k"
            << instruction.builtin->ExternalName();
    } else {
      out() << "   CodeStubAssembler(state_).TailCallBuiltin(Builtin::k"
            << instruction.builtin->ExternalName();
    }
    if (!instruction.builtin->signature().HasContextParameter()) {
      // Add dummy context parameter to satisfy the TailCallBuiltin signature.
      out() << ", TNode<Object>()";
    }
    for (const std::string& argument : arguments) {
      out() << ", " << argument;
    }
    out() << ");\n";
  } else {
    std::vector<std::string> result_names(result_types.size());
    for (size_t i = 0; i < result_types.size(); ++i) {
      result_names[i] = DefinitionToVariable(instruction.GetValueDefinition(i));
      decls() << "  TNode<" << result_types[i]->GetGeneratedTNodeTypeName()
              << "> " << result_names[i] << ";\n";
    }

    std::string lhs_name;
    std::string lhs_type;
    switch (result_types.size()) {
      case 0:
        // If a builtin call is annotated to never return, it has 0 return
        // types (defining true void builtins is not allowed).
        break;
      case 1:
        lhs_name = result_names[0];
        lhs_type = result_types[0]->GetGeneratedTNodeTypeName();
        break;
      case 2:
        // If a builtin returns two values, the return type is represented as a
        // TNode containing a pair. We need a temporary place to store that
        // result so we can unpack it into separate TNodes.
        lhs_name = result_names[0] + "_and_" + result_names[1];
        lhs_type = "PairT<" + result_types[0]->GetGeneratedTNodeTypeName() +
                   ", " + result_types[1]->GetGeneratedTNodeTypeName() + ">";
        decls() << "  TNode<" << lhs_type << "> " << lhs_name << ";\n";
        break;
      default:
        ReportError(
            "Torque can only call builtins that return one or two values, not ",
            result_types.size());
    }

    std::string catch_name =
        PreCallableExceptionPreparation(instruction.catch_block);
    Stack<std::string> pre_call_stack = *stack;

    for (const std::string& name : result_names) {
      stack->Push(name);
    }
    // Currently we don't support calling javascript builtins directly. If ever
    // needed, supporting that should be as easy as generating a call to
    // CodeStubAssembler::CallJSBuiltin here though.
    DCHECK(!instruction.builtin->IsJavaScript());
    if (result_types.empty()) {
      out() << "ca_.CallBuiltinVoid(Builtin::k"
            << instruction.builtin->ExternalName();
    } else {
      out() << "    " << lhs_name << " = ";
      out() << "ca_.CallBuiltin<" << lhs_type << ">(Builtin::k"
            << instruction.builtin->ExternalName();
    }
    if (!instruction.builtin->signature().HasContextParameter()) {
      // Add dummy context parameter to satisfy the CallBuiltin signature.
      out() << ", TNode<Object>()";
    }
    for (const std::string& argument : arguments) {
      out() << ", " << argument;
    }
    out() << ");\n";

    if (result_types.size() > 1) {
      for (size_t i = 0; i < result_types.size(); ++i) {
        out() << "    " << result_names[i] << " = ca_.Projection<" << i << ">("
              << lhs_name << ");\n";
      }
    }

    PostCallableExceptionPreparation(
        catch_name,
        result_types.empty() ? TypeOracle::GetVoidType() : result_types[0],
        instruction.catch_block, &pre_call_stack,
        instruction.GetExceptionObjectDefinition());
  }
}

void CSAGenerator::EmitInstruction(
    const CallBuiltinPointerInstruction& instruction,
    Stack<std::string>* stack) {
  std::vector<std::string> arguments = stack->PopMany(instruction.argc);
  std::string function = stack->Pop();
  std::vector<const Type*> result_types =
      LowerType(instruction.type->return_type());
  if (result_types.size() != 1) {
    ReportError("builtins must have exactly one result");
  }
  if (instruction.is_tailcall) {
    ReportError("tail-calls to builtin pointers are not supported");
  }

  DCHECK_EQ(1, instruction.GetValueDefinitionCount());
  stack->Push(DefinitionToVariable(instruction.GetValueDefinition(0)));
  std::string generated_type = result_types[0]->GetGeneratedTNodeTypeName();
  decls() << "  TNode<" << generated_type << "> " << stack->Top() << ";\n";
  out() << stack->Top() << " = ";
  if (generated_type != "Object") out() << "TORQUE_CAST(";
  out() << "CodeStubAssembler(state_).CallBuiltinPointer(Builtins::"
           "CallInterfaceDescriptorFor("
           "ExampleBuiltinForTorqueFunctionPointerType("
        << instruction.type->function_pointer_type_id() << ")), " << function;
  if (!instruction.type->HasContextParameter()) {
    // Add dummy context parameter to satisfy the CallBuiltinPointer signature.
    out() << ", TNode<Object>()";
  }
  for (const std::string& argument : arguments) {
    out() << ", " << argument;
  }
  out() << ")";
  if (generated_type != "Object") out() << ")";
  out() << ";\n";
}

std::string CSAGenerator::PreCallableExceptionPreparation(
    std::optional<Block*> catch_block) {
  std::string catch_name;
  if (catch_block) {
    catch_name = FreshCatchName();
    out() << "    compiler::CodeAssemblerExceptionHandlerLabel " << catch_name
          << "__label(&ca_, compiler::CodeAssemblerLabel::kDeferred);\n";
    out() << "    { compiler::ScopedExceptionHandler s(&ca_, &" << catch_name
          << "__label);\n";
  }
  return catch_name;
}

void CSAGenerator::PostCallableExceptionPreparation(
    const std::string& catch_name, const Type* return_type,
    std::optional<Block*> catch_block, Stack<std::string>* stack,
    const std::optional<DefinitionLocation>& exception_object_definition) {
  if (catch_block) {
    DCHECK(exception_object_definition);
    std::string block_name = BlockName(*catch_block);
    out() << "    }\n";
    out() << "    if (" << catch_name << "__label.is_used()) {\n";
    out() << "      compiler::CodeAssemblerLabel " << catch_name
          << "_skip(&ca_);\n";
    if (!return_type->IsNever()) {
      out() << "      ca_.Goto(&" << catch_name << "_skip);\n";
    }
    decls() << "      TNode<Object> "
            << DefinitionToVariable(*exception_object_definition) << ";\n";
    out() << "      ca_.Bind(&" << catch_name << "__label, &"
          << DefinitionToVariable(*exception_object_definition) << ");\n";
    out() << "      ca_.Goto(&" << block_name;

    DCHECK_EQ(stack->Size() + 1, (*catch_block)->InputDefinitions().Size());
    const auto& input_definitions = (*catch_block)->InputDefinitions();
    for (BottomOffset i = {0}; i < input_definitions.AboveTop(); ++i) {
      if (input_definitions.Peek(i).IsPhiFromBlock(*catch_block)) {
        if (i < stack->AboveTop()) {
          out() << ", " << stack->Peek(i);
        } else {
          DCHECK_EQ(i, stack->AboveTop());
          out() << ", " << DefinitionToVariable(*exception_object_definition);
        }
      }
    }
    out() << ");\n";

    if (!return_type->IsNever()) {
      out() << "      ca_.Bind(&" << catch_name << "_skip);\n";
    }
    out() << "    }\n";
  }
}

void CSAGenerator::EmitInstruction(const CallRuntimeInstruction& instruction,
                                   Stack<std::string>* stack) {
  std::vector<std::string> arguments = stack->PopMany(instruction.argc);
  const Type* return_type =
      instruction.runtime_function->signature().return_type;
  std::vector<const Type*> result_types;
  if (return_type != TypeOracle::GetNeverType()) {
    result_types = LowerType(return_type);
  }
  if (result_types.size() > 1) {
    ReportError("runtime function must have at most one result");
  }
  if (instruction.is_tailcall) {
    out() << "    CodeStubAssembler(state_).TailCallRuntime(Runtime::k"
          << instruction.runtime_function->ExternalName() << ", ";
    PrintCommaSeparatedList(out(), arguments);
    out() << ");\n";
  } else {
    std::string result_name;
    if (result_types.size() == 1) {
      result_name = DefinitionToVariable(instruction.GetValueDefinition(0));
      decls() << "  TNode<" << result_types[0]->GetGeneratedTNodeTypeName()
              << "> " << result_name << ";\n";
    }
    std::string catch_name =
        PreCallableExceptionPreparation(instruction.catch_block);
    Stack<std::string> pre_call_stack = *stack;
    if (result_types.size() == 1) {
      std::string generated_type = result_types[0]->GetGeneratedTNodeTypeName();
      stack->Push(result_name);
      out() << "    " << result_name << " = ";
      if (generated_type != "Object") out() << "TORQUE_CAST(";
      out() << "CodeStubAssembler(state_).CallRuntime(Runtime::k"
            << instruction.runtime_function->ExternalName() << ", ";
      PrintCommaSeparatedList(out(), arguments);
      out() << ")";
      if (generated_type != "Object") out() << ")";
      out() << "; \n";
    } else {
      DCHECK_EQ(0, result_types.size());
      out() << "    CodeStubAssembler(state_).CallRuntime(Runtime::k"
            << instruction.runtime_function->ExternalName() << ", ";
      PrintCommaSeparatedList(out(), arguments);
      out() << ");\n";
      if (return_type == TypeOracle::GetNeverType()) {
        out() << "    CodeStubAssembler(state_).Unreachable();\n";
      } else {
        DCHECK(return_type == TypeOracle::GetVoidType());
      }
    }
    PostCallableExceptionPreparation(
        catch_name, return_type, instruction.catch_block, &pre_call_stack,
        instruction.GetExceptionObjectDefinition());
  }
}

void CSAGenerator::EmitInstruction(const BranchInstruction& instruction,
                                   Stack<std::string>* stack) {
  out() << "    ca_.Branch(" << stack->Pop() << ", &"
        << BlockName(instruction.if_true) << ", std::vector<compiler::Node*>{";

  const auto& true_definitions = instruction.if_true->InputDefinitions();
  DCHECK_EQ(stack->Size(), true_definitions.Size());
  bool first = true;
  for (BottomOffset i = {0}; i < stack->AboveTop(); ++i) {
    if (true_definitions.Peek(i).IsPhiFromBlock(instruction.if_true)) {
      if (!first) out() << ", ";
      out() << stack->Peek(i);
      first = false;
    }
  }

  out() << "}, &" << BlockName(instruction.if_false)
        << ", std::vector<compiler::Node*>{";

  const auto& false_definitions = instruction.if_false->InputDefinitions();
  DCHECK_EQ(stack->Size(), false_definitions.Size());
  first = true;
  for (BottomOffset i = {0}; i < stack->AboveTop(); ++i) {
    if (false_definitions.Peek(i).IsPhiFromBlock(instruction.if_false)) {
      if (!first) out() << ", ";
      out() << stack->Peek(i);
      first = false;
    }
  }

  out() << "});\n";
}

void CSAGenerator::EmitInstruction(
    const ConstexprBranchInstruction& instruction, Stack<std::string>* stack) {
  out() << "    if ((" << instruction.condition << ")) {\n";
  out() << "      ca_.Goto(&" << BlockName(instruction.if_true);

  const auto& true_definitions = instruction.if_true->InputDefinitions();
  DCHECK_EQ(stack->Size(), true_definitions.Size());
  for (BottomOffset i = {0}; i < stack->AboveTop(); ++i) {
    if (true_definitions.Peek(i).IsPhiFromBlock(instruction.if_true)) {
      out() << ", " << stack->Peek(i);
    }
  }

  out() << ");\n";
  out() << "    } else {\n";
  out() << "      ca_.Goto(&" << BlockName(instruction.if_false);

  const auto& false_definitions = instruction.if_false->InputDefinitions();
  DCHECK_EQ(stack->Size(), false_definitions.Size());
  for (BottomOffset i = {0}; i < stack->AboveTop(); ++i) {
    if (false_definitions.Peek(i).IsPhiFromBlock(instruction.if_false)) {
      out() << ", " << stack->Peek(i);
    }
  }

  out() << ");\n";
  out() << "    }\n";
}

void CSAGenerator::EmitInstruction(const GotoInstruction& instruction,
                                   Stack<std::string>* stack) {
  out() << "    ca_.Goto(&" << BlockName(instruction.destination);
  const auto& destination_definitions =
      instruction.destination->InputDefinitions();
  DCHECK_EQ(stack->Size(), destination_definitions.Size());
  for (BottomOffset i = {0}; i < stack->AboveTop(); ++i) {
    if (destination_definitions.Peek(i).IsPhiFromBlock(
            instruction.destination)) {
      out() << ", " << stack->Peek(i);
    }
  }
  out() << ");\n";
}

void CSAGenerator::EmitInstruction(const GotoExternalInstruction& instruction,
                                   Stack<std::string>* stack) {
  for (auto it = instruction.variable_names.rbegin();
       it != instruction.variable_names.rend(); ++it) {
    out() << "    *" << *it << " = " << stack->Pop() << ";\n";
  }
  out() << "    ca_.Goto(" << instruction.destination << ");\n";
}

void CSAGenerator::EmitInstruction(const ReturnInstruction& instruction,
                                   Stack<std::string>* stack) {
  if (*linkage_ == Builtin::kVarArgsJavaScript) {
    out() << "    " << ARGUMENTS_VARIABLE_STRING << ".PopAndReturn(";
  } else {
    out() << "    CodeStubAssembler(state_).Return(";
  }
  std::vector<std::string> values = stack->PopMany(instruction.count);
  PrintCommaSeparatedList(out(), values);
  out() << ");\n";
}

void CSAGenerator::EmitInstruction(const PrintErrorInstruction& instruction,
                                   Stack<std::string>* stack) {
  out() << "    CodeStubAssembler(state_).PrintErr("
        << StringLiteralQuote(instruction.message) << ");\n";
}

void CSAGenerator::EmitInstruction(const AbortInstruction& instruction,
                                   Stack<std::string>* stack) {
  switch (instruction.kind) {
    case AbortInstruction::Kind::kUnreachable:
      DCHECK(instruction.message.empty());
      out() << "    CodeStubAssembler(state_).Unreachable();\n";
      break;
    case AbortInstruction::Kind::kDebugBreak:
      DCHECK(instruction.message.empty());
      out() << "    CodeStubAssembler(state_).DebugBreak();\n";
      break;
    case AbortInstruction::Kind::kAssertionFailure: {
      std::string file = StringLiteralQuote(
          SourceFileMap::PathFromV8Root(instruction.pos.source));
      out() << "    {\n";
      out() << "      auto pos_stack = ca_.GetMacroSourcePositionStack();\n";
      out() << "      pos_stack.push_back({" << file << ", "
            << instruction.pos.start.line + 1 << "});\n";
      out() << "      CodeStubAssembler(state_).FailAssert("
            << StringLiteralQuote(instruction.message) << ", pos_stack);\n";
      out() << "    }\n";
      break;
    }
  }
}

void CSAGenerator::EmitInstruction(const UnsafeCastInstruction& instruction,
                                   Stack<std::string>* stack) {
  const std::string str =
      "ca_.UncheckedCast<" +
      instruction.destination_type->GetGeneratedTNodeTypeName() + ">(" +
      stack->Top() + ")";
  stack->Poke(stack->AboveTop() - 1, str);
  SetDefinitionVariable(instruction.GetValueDefinition(), str);
}

void CSAGenerator::EmitInstruction(const LoadReferenceInstruction& instruction,
                                   Stack<std::string>* stack) {
  std::string result_name =
      DefinitionToVariable(instruction.GetValueDefinition());

  std::string offset = stack->Pop();
  std::string object = stack->Pop();
  stack->Push(result_name);

  decls() << "  " << instruction.type->GetGeneratedTypeName() << " "
          << result_name << ";\n";
  out() << "    " << result_name
        << " = CodeStubAssembler(state_).LoadReference<"
        << instruction.type->GetGeneratedTNodeTypeName()
        << ">(CodeStubAssembler::Reference{" << object << ", " << offset
        << "});\n";
}

void CSAGenerator::EmitInstruction(const StoreReferenceInstruction& instruction,
                                   Stack<std::string>* stack) {
  std::string value = stack->Pop();
  std::string offset = stack->Pop();
  std::string object = stack->Pop();

  out() << "    CodeStubAssembler(state_).StoreReference<"
        << instruction.type->GetGeneratedTNodeTypeName()
        << ">(CodeStubAssembler::"
           "Reference{"
        << object << ", " << offset << "}, " << value << ");\n";
}

namespace {
std::string GetBitFieldSpecialization(const Type* container,
                                      const BitField& field) {
  auto smi_tagged_type =
      Type::MatchUnaryGeneric(container, TypeOracle::GetSmiTaggedGeneric());
  std::string container_type = smi_tagged_type
                                   ? "uintptr_t"
                                   : container->GetConstexprGeneratedTypeName();
  int offset = smi_tagged_type
                   ? field.offset + TargetArchitecture::SmiTagAndShiftSize()
                   : field.offset;
  std::stringstream stream;
  stream << "base::BitField<"
         << field.name_and_type.type->GetConstexprGeneratedTypeName() << ", "
         << offset << ", " << field.num_bits << ", " << container_type << ">";
  return stream.str();
}
}  // namespace

void CSAGenerator::EmitInstruction(const LoadBitFieldInstruction& instruction,
                                   Stack<std::string>* stack) {
  std::string result_name =
      DefinitionToVariable(instruction.GetValueDefinition());

  std::string bit_field_struct = stack->Pop();
  stack->Push(result_name);

  const Type* struct_type = instruction.bit_field_struct_type;
  const Type* field_type = instruction.bit_field.name_and_type.type;
  auto smi_tagged_type =
      Type::MatchUnaryGeneric(struct_type, TypeOracle::GetSmiTaggedGeneric());
  bool struct_is_pointer_size =
      IsPointerSizeIntegralType(struct_type) || smi_tagged_type;
  DCHECK_IMPLIES(!struct_is_pointer_size, Is32BitIntegralType(struct_type));
  bool field_is_pointer_size = IsPointerSizeIntegralType(field_type);
  DCHECK_IMPLIES(!field_is_pointer_size, Is32BitIntegralType(field_type));
  std::string struct_word_type = struct_is_pointer_size ? "WordT" : "Word32T";
  std::string decoder =
      struct_is_pointer_size
          ? (field_is_pointer_size ? "DecodeWord" : "DecodeWord32FromWord")
          : (field_is_pointer_size ? "DecodeWordFromWord32" : "DecodeWord32");

  decls() << "  " << field_type->GetGeneratedTypeName() << " " << result_name
          << ";\n";

  if (smi_tagged_type) {
    // If the container is a SMI, then UncheckedCast is insufficient and we must
    // use a bit cast.
    bit_field_struct =
        "ca_.BitcastTaggedToWordForTagAndSmiBits(" + bit_field_struct + ")";
  }

  out() << "    " << result_name << " = ca_.UncheckedCast<"
        << field_type->GetGeneratedTNodeTypeName()
        << ">(CodeStubAssembler(state_)." << decoder << "<"
        << GetBitFieldSpecialization(struct_type, instruction.bit_field)
        << ">(ca_.UncheckedCast<" << struct_word_type << ">("
        << bit_field_struct << ")));\n";
}

void CSAGenerator::EmitInstruction(const StoreBitFieldInstruction& instruction,
                                   Stack<std::string>* stack) {
  std::string result_name =
      DefinitionToVariable(instruction.GetValueDefinition());

  std::string value = stack->Pop();
  std::string bit_field_struct = stack->Pop();
  stack->Push(result_name);

  const Type* struct_type = instruction.bit_field_struct_type;
  const Type* field_type = instruction.bit_field.name_and_type.type;
  auto smi_tagged_type =
      Type::MatchUnaryGeneric(struct_type, TypeOracle::GetSmiTaggedGeneric());
  bool struct_is_pointer_size =
      IsPointerSizeIntegralType(struct_type) || smi_tagged_type;
  DCHECK_IMPLIES(!struct_is_pointer_size, Is32BitIntegralType(struct_type));
  bool field_is_pointer_size = IsPointerSizeIntegralType(field_type);
  DCHECK_IMPLIES(!field_is_pointer_size, Is32BitIntegralType(field_type));
  std::string struct_word_type = struct_is_pointer_size ? "WordT" : "Word32T";
  std::string field_word_type = field_is_pointer_size ? "UintPtrT" : "Uint32T";
  std::string encoder =
      struct_is_pointer_size
          ? (field_is_pointer_size ? "UpdateWord" : "UpdateWord32InWord")
          : (field_is_pointer_size ? "UpdateWordInWord32" : "UpdateWord32");

  decls() << "  " << struct_type->GetGeneratedTypeName() << " " << result_name
          << ";\n";

  if (smi_tagged_type) {
    // If the container is a SMI, then UncheckedCast is insufficient and we must
    // use a bit cast.
    bit_field_struct =
        "ca_.BitcastTaggedToWordForTagAndSmiBits(" + bit_field_struct + ")";
  }

  std::string result_expression =
      "CodeStubAssembler(state_)." + encoder + "<" +
      GetBitFieldSpecialization(struct_type, instruction.bit_field) +
      ">(ca_.UncheckedCast<" + struct_word_type + ">(" + bit_field_struct +
      "), ca_.UncheckedCast<" + field_word_type + ">(" + value + ")" +
      (instruction.starts_as_zero ? ", true" : "") + ")";

  if (smi_tagged_type) {
    result_expression =
        "ca_.BitcastWordToTaggedSigned(" + result_expression + ")";
  }

  out() << "    " << result_name << " = ca_.UncheckedCast<"
        << struct_type->GetGeneratedTNodeTypeName() << ">(" << result_expression
        << ");\n";
}

// static
void CSAGenerator::EmitCSAValue(VisitResult result,
                                const Stack<std::string>& values,
                                std::ostream& out) {
  if (!result.IsOnStack()) {
    out << result.constexpr_value();
  } else if (auto struct_type = result.type()->StructSupertype()) {
    out << (*struct_type)->GetGeneratedTypeName() << "{";
    bool first = true;
    for (auto& field : (*struct_type)->fields()) {
      if (!first) {
        out << ", ";
      }
      first = false;
      EmitCSAValue(ProjectStructField(result, field.name_and_type.name), values,
                   out);
    }
    out << "}";
  } else {
    DCHECK_EQ(1, result.stack_range().Size());
    out << result.type()->GetGeneratedTypeName() << "{"
        << values.Peek(result.stack_range().begin()) << "}";
  }
}

}  // namespace v8::internal::torque

"""

```