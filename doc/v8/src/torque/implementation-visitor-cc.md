Response:
My thinking process to answer the request about `implementation-visitor.cc` went like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code snippet, focusing on its role in the v8 Torque compiler, its relationship to JavaScript, and potential programming errors it might help prevent. The "part 1 of 7" suggests this is a broader exploration of Torque.

2. **Identify the Core Class:** The first line `#include "src/torque/implementation-visitor.h"` immediately tells me the central class is `ImplementationVisitor`. This will be the focal point of my analysis.

3. **Analyze Includes:**  I scanned the `#include` directives to get a high-level understanding of what the `ImplementationVisitor` interacts with:
    * **Basic C++:** `<algorithm>`, `<iomanip>`, `<optional>`, `<string>` indicate standard C++ utilities are used.
    * **v8 Core:**  Headers like `"src/common/globals.h"`, `"src/numbers/integer-literal-inl.h"` suggest this code is deeply embedded within the v8 project.
    * **Torque-Specific:**  The majority of includes like `"src/torque/cc-generator.h"`, `"src/torque/cfg.h"`, `"src/torque/types.h"`, etc., confirm this file is a core part of the Torque compiler. These names hint at compiler phases or data structures (code generation, control flow graph, type system).

4. **Look for Key Methods:** I scanned the class definition for important methods. The `Visit()` methods are immediately striking because they appear to be the primary way the visitor interacts with different parts of the Torque Abstract Syntax Tree (AST). The switch statements within the `Visit()` methods for `Expression` and `Statement` confirm this.

5. **Infer Functionality from Method Names and Logic:**
    * **`Visit(Expression*)` and `Visit(Statement*)`:** These strongly suggest the core responsibility of the class is to traverse and process the Torque AST.
    * **`BeginGeneratedFiles()` and `EndGeneratedFiles()`:**  This points to the class being involved in the output generation phase, likely creating C++ and header files. The code inside these methods confirms this by manipulating `streams.csa_cc`, `streams.csa_header`, etc.
    * **`Visit(NamespaceConstant*)`, `Visit(TypeAlias*)`, `Visit(TorqueMacro*)`, `Visit(Builtin*)`:** These `Visit()` methods, taking specific AST node types as arguments, indicate the class has specialized logic for handling different Torque language constructs.
    * **`InlineMacro()`:** This clearly deals with inlining macro expansions, a common compiler optimization technique.
    * **`Visit(VarDeclarationStatement*)` and `Visit(TailCallStatement*)`:** These handle specific statement types within Torque.

6. **Connect to Torque's Purpose:** Knowing that Torque is a language for writing optimized low-level code within v8, I can infer that `ImplementationVisitor` is responsible for translating Torque code into C++ code that interacts with v8's internal APIs.

7. **Identify JavaScript Relevance:**  The `Visit(Builtin*)` method is a crucial point. "Builtins" in v8 are often the underlying implementations of JavaScript's built-in functions and objects. The code within `Visit(Builtin*)` shows how Torque builtins are translated into C++ functions using the CodeStubAssembler (CSA), a v8 component for low-level code generation. This establishes a clear link to JavaScript functionality.

8. **Consider Potential Programming Errors:**  As I analyzed the code, I looked for error reporting mechanisms. The use of `ReportError()` and `Error().Position().Throw()` indicates that the `ImplementationVisitor` performs semantic checks and can detect errors in Torque code. Examples like uninitialized constants, incorrect implicit parameter types for builtins, and macros not returning values when expected came to mind.

9. **Formulate JavaScript Examples:**  Based on the understanding of builtins, I could then create JavaScript examples that would correspond to the Torque code processed by `ImplementationVisitor`. For example, `Array.prototype.push` would be a potential builtin implemented in Torque.

10. **Develop Hypothetical Input/Output:**  To illustrate code logic, I considered how a simple Torque macro or builtin might be translated. A macro adding two numbers would be a good example, showing how the visitor would process the input arguments and generate corresponding C++ code.

11. **Structure the Answer:** Finally, I organized my findings into the requested sections:
    * List of functions.
    * Explanation of `.tq` files.
    * JavaScript relationship with examples.
    * Code logic illustration with input/output.
    * Common programming errors.
    * Overall function summary.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on low-level CSA details. I then realized the request asked for a *functional* overview, so I shifted to a higher level of abstraction, explaining *what* the class does rather than *how* it does it at the CSA level.
* I considered whether to go into detail about the different output types (kCC, kCSA, kCCDebug), but decided to keep the explanation more general for this "part 1" summary. I noted their existence but didn't delve into their specifics.
* I made sure to explicitly connect the concepts back to the prompt's constraints, such as the `.tq` file check and the request for JavaScript examples.

By following these steps, I could generate a comprehensive and accurate answer to the request, breaking down the functionality of `implementation-visitor.cc` in the context of the v8 Torque compiler.
好的，根据你提供的 v8 源代码 `v8/src/torque/implementation-visitor.cc` 的第一部分，我们可以归纳出以下功能：

**主要功能归纳：**

`ImplementationVisitor` 类是 Torque 编译器的核心组件之一，它的主要职责是**遍历 Torque 的抽象语法树 (AST)，并将 Torque 代码的具体实现逻辑生成相应的 C++ 代码**。 这些生成的 C++ 代码会使用到 v8 的 CodeStubAssembler (CSA) 以及底层的 C++ API。

**具体功能点：**

1. **AST 遍历和处理:**
   - `Visit(Expression* expr)` 和 `Visit(Statement* stmt)` 方法是入口点，用于根据表达式和语句的不同类型，分发到具体的 `Visit` 方法进行处理。
   - 针对各种 Torque 语法结构（例如：常量、类型别名、宏、内置函数、变量声明、尾调用等）都有对应的 `Visit` 方法。

2. **C++ 代码生成:**
   - 负责生成 `.cc` 和 `.h` 文件，这些文件包含了 Torque 代码的 C++ 实现。
   - 使用 `cpp::File` 类来构建 C++ 代码文件。
   - 针对 CSA 代码生成，使用 `CSAGenerator` 类。
   - 针对 C++ 代码生成 (例如，用于计算字段偏移量)，使用 `CCGenerator` 类。
   - 可以处理包含类定义的 Torque 源文件，并生成相应的 C++ 类定义代码。

3. **宏展开 (Inlining):**
   - `InlineMacro()` 方法负责将 Torque 宏调用展开为实际的代码。
   - 使用 `MacroInliningScope` 来防止宏的递归调用导致栈溢出。

4. **处理命名空间常量:**
   - `Visit(NamespaceConstant* decl)` 方法生成命名空间常量的 C++ 代码。

5. **处理类型别名:**
   - `Visit(TypeAlias* alias)` 方法处理类型别名，进行一些检查，例如外部类是否在默认命名空间。

6. **处理 Torque 宏和方法:**
   - `Visit(TorqueMacro* macro)` 和 `Visit(Method* method)` 方法生成 Torque 宏和方法的 C++ 实现。

7. **处理内置函数 (Builtins):**
   - `Visit(Builtin* builtin)` 方法生成 v8 内置函数的 C++ 实现，这些内置函数是 JavaScript 功能的底层实现。
   - 可以处理不同类型的内置函数，例如 JavaScript 函数和 Stub 函数。
   - 可以处理 JavaScript 内置函数的参数 (包括隐式参数如 `context`, `receiver`) 和变长参数。
   - 可以插入使用计数器的代码。

8. **处理变量声明:**
   - `Visit(VarDeclarationStatement* stmt)` 方法处理变量声明，包括常量和非常量，以及初始化。

9. **处理尾调用:**
   - `Visit(TailCallStatement* stmt)` 方法处理尾调用。

10. **管理作用域和绑定:**
    - 使用 `StackScope`, `BindingsManagersScope`, `BlockBindings` 等来管理变量和标签的作用域和绑定关系。

11. **调试宏生成:**
    - `BeginDebugMacrosFile()` 和 `EndDebugMacrosFile()` 方法用于生成调试宏相关的 C++ 代码。

**关于 `.tq` 文件和 JavaScript 关系：**

- 你的判断是正确的：**如果 `v8/src/torque/implementation-visitor.cc` 以 `.tq` 结尾，那么它就是一个 v8 Torque 源代码文件。** 然而，实际的文件名是 `.cc`，这表明 `implementation-visitor.cc` 是 Torque 编译器的实现代码，它**处理**以 `.tq` 结尾的 Torque 源代码文件。

- **与 JavaScript 的功能关系:** `ImplementationVisitor` 生成的 C++ 代码很多时候直接关系到 JavaScript 的功能实现。 v8 中许多内置的 JavaScript 对象和方法，例如 `Array.prototype.push`， `Object.prototype.toString` 等，它们的底层实现就是用 Torque 编写的。

**JavaScript 举例说明：**

假设有一个用 Torque 定义的内置函数 `ArrayPush`，它实现了 `Array.prototype.push` 的部分逻辑。  `ImplementationVisitor` 会遍历这个 `ArrayPush` 的 Torque 代码，并生成相应的 C++ 代码。 当 JavaScript 代码执行 `myArray.push(value)` 时，最终会调用到 `ImplementationVisitor` 生成的 C++ 代码。

```javascript
// JavaScript 代码
const myArray = [1, 2, 3];
myArray.push(4); // 这里会调用到底层 Torque 生成的 C++ 代码
```

**代码逻辑推理 (假设输入与输出)：**

假设有一个简单的 Torque 宏 `Add(a: int, b: int): int`，其定义如下：

```torque
macro Add(a: int, b: int): int {
  return a + b;
}
```

**假设输入 (传递给 `ImplementationVisitor` 的 AST 节点)：**  一个表示 `Add` 宏定义的 `TorqueMacro` 类型的 AST 节点。

**假设输出 (由 `ImplementationVisitor` 生成的 C++ 代码)：**

```cpp
// 在相应的 .cc 文件中
TNode<IntPtrT> Add(TNode<IntPtrT> a, TNode<IntPtrT> b) {
  compiler::CodeAssembler ca_(state_);
  compiler::CodeAssembler::SourcePositionScope pos_scope(&ca_);
  TNode<IntPtrT> tmpResult_0_0;
  tmpResult_0_0 = (a) + (b);
  return tmpResult_0_0;
}

// 在相应的 .h 文件中
TNode<IntPtrT> Add(TNode<IntPtrT> a, TNode<IntPtrT> b);
```

**用户常见的编程错误 (可能由 Torque 或 `ImplementationVisitor` 检测到)：**

1. **类型不匹配:** 在 Torque 代码中，如果传递给宏或内置函数的参数类型与声明的类型不符，`ImplementationVisitor` 在类型检查阶段会报错。

   ```torque
   // 错误示例：传递字符串给期望整数的宏
   macro Print(value: int) {
     // ...
   }
   Print("hello"); // ImplementationVisitor 会检测到类型错误
   ```

2. **宏或内置函数没有返回值 (当期望有返回值时):** 如果 Torque 声明了一个有返回值的宏或内置函数，但在其实现中没有显式返回，`ImplementationVisitor` 会发出警告或错误。

   ```torque
   macro MaybeReturn(): int {
     let condition: bool = false;
     if (condition) {
       return 1;
     }
     // 这里缺少返回值，ImplementationVisitor 可能会报错
   }
   ```

3. **const 变量未初始化:** 如果在 Torque 中声明了一个 `const` 变量但没有进行初始化，`ImplementationVisitor` 会报错。

   ```torque
   const myConstant: int; // 错误：const 变量必须初始化
   ```

**总结:**

`ImplementationVisitor` 是 Torque 编译器中至关重要的一个组件，它负责将高级的 Torque 语言转换为 v8 可以执行的底层 C++ 代码。它处理了 Torque 语言的各种语法结构，并确保生成的代码能够正确地实现预期的功能，同时也能检测出一些常见的编程错误。 它是连接 Torque 语言和 v8 底层实现的关键桥梁。

Prompt: 
```
这是目录为v8/src/torque/implementation-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/implementation-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/implementation-visitor.h"

#include <algorithm>
#include <iomanip>
#include <optional>
#include <string>

#include "src/common/globals.h"
#include "src/numbers/integer-literal-inl.h"
#include "src/torque/cc-generator.h"
#include "src/torque/cfg.h"
#include "src/torque/constants.h"
#include "src/torque/cpp-builder.h"
#include "src/torque/csa-generator.h"
#include "src/torque/declaration-visitor.h"
#include "src/torque/global-context.h"
#include "src/torque/kythe-data.h"
#include "src/torque/parameter-difference.h"
#include "src/torque/server-data.h"
#include "src/torque/source-positions.h"
#include "src/torque/type-inference.h"
#include "src/torque/type-visitor.h"
#include "src/torque/types.h"
#include "src/torque/utils.h"

namespace v8::internal::torque {

uint64_t next_unique_binding_index = 0;

// Sadly, 'using std::string_literals::operator""s;' is bugged in MSVC (see
// https://developercommunity.visualstudio.com/t/Incorrect-warning-when-using-standard-st/673948).
// TODO(nicohartmann@): Change to 'using std::string_literals::operator""s;'
// once this is fixed.
using namespace std::string_literals;  // NOLINT(build/namespaces)

namespace {
const char* BuiltinIncludesMarker = "// __BUILTIN_INCLUDES_MARKER__\n";
}  // namespace

VisitResult ImplementationVisitor::Visit(Expression* expr) {
  CurrentSourcePosition::Scope scope(expr->pos);
  switch (expr->kind) {
#define ENUM_ITEM(name)        \
  case AstNode::Kind::k##name: \
    return Visit(name::cast(expr));
    AST_EXPRESSION_NODE_KIND_LIST(ENUM_ITEM)
#undef ENUM_ITEM
    default:
      UNREACHABLE();
  }
}

const Type* ImplementationVisitor::Visit(Statement* stmt) {
  CurrentSourcePosition::Scope scope(stmt->pos);
  StackScope stack_scope(this);
  const Type* result;
  switch (stmt->kind) {
#define ENUM_ITEM(name)               \
  case AstNode::Kind::k##name:        \
    result = Visit(name::cast(stmt)); \
    break;
    AST_STATEMENT_NODE_KIND_LIST(ENUM_ITEM)
#undef ENUM_ITEM
    default:
      UNREACHABLE();
  }
  DCHECK_EQ(result == TypeOracle::GetNeverType(),
            assembler().CurrentBlockIsComplete());
  return result;
}

void ImplementationVisitor::BeginGeneratedFiles() {
  std::set<SourceId> contains_class_definitions;
  std::set<SourceId> contains_class_asserts;
  for (const ClassType* type : TypeOracle::GetClasses()) {
    if (type->ShouldGenerateCppClassDefinitions()) {
      contains_class_definitions.insert(type->AttributedToFile());
    }
    if (type->ShouldGenerateCppObjectDefinitionAsserts() ||
        type->ShouldGenerateCppObjectLayoutDefinitionAsserts()) {
      contains_class_asserts.insert(type->AttributedToFile());
    }
  }

  for (SourceId source : SourceFileMap::AllSources()) {
    auto& streams = GlobalContext::GeneratedPerFile(source);
    // Output beginning of CSA .cc file.
    {
      cpp::File& file = streams.csa_cc;

      for (const std::string& include_path : GlobalContext::CppIncludes()) {
        file << "#include " << StringLiteralQuote(include_path) << "\n";
      }
      file << "#include \"src/codegen/code-stub-assembler-inl.h\"\n";

      file << "// Required Builtins:\n";
      file << "#include \"torque-generated/" +
                  SourceFileMap::PathFromV8RootWithoutExtension(source) +
                  "-tq-csa.h\"\n";
      // Now that required include files are collected while generting the file,
      // we only know the full set at the end. Insert a marker here that is
      // replaced with the list of includes at the very end.
      // TODO(nicohartmann@): This is not the most beautiful way to do this,
      // replace once the cpp file builder is available, where this can be
      // handled easily.
      file << BuiltinIncludesMarker;
      file << "\n";

      streams.csa_cc.BeginNamespace("v8", "internal");
      streams.csa_ccfile << "\n";
    }
    // Output beginning of CSA .h file.
    {
      cpp::File& file = streams.csa_header;
      std::string header_define =
          "V8_GEN_TORQUE_GENERATED_" +
          UnderlinifyPath(SourceFileMap::PathFromV8Root(source)) + "_CSA_H_";
      streams.csa_header.BeginIncludeGuard(header_define);
      file << "#include \"src/builtins/torque-csa-header-includes.h\"\n";
      file << "\n";

      streams.csa_header.BeginNamespace("v8", "internal");
      streams.csa_headerfile << "\n";
    }
    // Output beginning of class definition .cc file.
    {
      cpp::File& file = streams.class_definition_cc;
      if (contains_class_definitions.count(source) != 0) {
        file << "#include \""
             << SourceFileMap::PathFromV8RootWithoutExtension(source)
             << "-inl.h\"\n\n";
        file << "#include \"torque-generated/class-verifiers.h\"\n";
        file << "#include \"src/objects/instance-type-inl.h\"\n\n";
      }
      if (contains_class_asserts.count(source) != 0) {
        file << "#include \""
             << SourceFileMap::PathFromV8RootWithoutExtension(source)
             << ".h\"\n\n";
      }

      streams.class_definition_cc.BeginNamespace("v8", "internal");
      streams.class_definition_ccfile << "\n";
    }
  }
}

void ImplementationVisitor::EndGeneratedFiles() {
  for (SourceId file : SourceFileMap::AllSources()) {
    auto& streams = GlobalContext::GeneratedPerFile(file);

    // Output ending of CSA .cc file.
    streams.csa_cc.EndNamespace("v8", "internal");

    // Output ending of CSA .h file.
    {
      std::string header_define =
          "V8_GEN_TORQUE_GENERATED_" +
          UnderlinifyPath(SourceFileMap::PathFromV8Root(file)) + "_CSA_H_";

      streams.csa_header.EndNamespace("v8", "internal");
      streams.csa_headerfile << "\n";
      streams.csa_header.EndIncludeGuard(header_define);
    }

    // Output ending of class definition .cc file.
    streams.class_definition_cc.EndNamespace("v8", "internal");
  }
}

void ImplementationVisitor::BeginDebugMacrosFile() {
  // TODO(torque-builer): Can use builder for debug_macros_*_
  std::ostream& source = debug_macros_cc_;
  std::ostream& header = debug_macros_h_;

  source << "#include \"torque-generated/debug-macros.h\"\n\n";
  source << "#include \"src/objects/swiss-name-dictionary.h\"\n";
  source << "#include \"src/objects/ordered-hash-table.h\"\n";
  source << "#include \"src/torque/runtime-support.h\"\n";
  source << "#include \"tools/debug_helper/debug-macro-shims.h\"\n";
  source << "#include \"include/v8-internal.h\"\n";
  source << "\n";

  source << "namespace v8 {\n"
         << "namespace internal {\n"
         << "namespace debug_helper_internal {\n"
         << "\n";

  const char* kHeaderDefine = "V8_GEN_TORQUE_GENERATED_DEBUG_MACROS_H_";
  header << "#ifndef " << kHeaderDefine << "\n";
  header << "#define " << kHeaderDefine << "\n\n";
  header << "#include \"tools/debug_helper/debug-helper-internal.h\"\n";
  header << "#include \"src/numbers/integer-literal.h\"\n";
  header << "\n";

  header << "namespace v8 {\n"
         << "namespace internal {\n"
         << "namespace debug_helper_internal {\n"
         << "\n";
}

void ImplementationVisitor::EndDebugMacrosFile() {
  // TODO(torque-builder): Can use builder for debug_macros_*_
  std::ostream& source = debug_macros_cc_;
  std::ostream& header = debug_macros_h_;

  source << "}  // namespace internal\n"
         << "}  // namespace v8\n"
         << "}  // namespace debug_helper_internal\n"
         << "\n";

  header << "\n}  // namespace internal\n"
         << "}  // namespace v8\n"
         << "}  // namespace debug_helper_internal\n"
         << "\n";
  header << "#endif  // V8_GEN_TORQUE_GENERATED_DEBUG_MACROS_H_\n";
}

void ImplementationVisitor::Visit(NamespaceConstant* decl) {
  Signature signature{{},           std::nullopt, {{}, false}, 0,
                      decl->type(), {},           false};

  BindingsManagersScope bindings_managers_scope;

  cpp::Function f =
      GenerateFunction(nullptr, decl->external_name(), signature, {});

  f.PrintDeclaration(csa_headerfile());

  f.PrintDefinition(csa_ccfile(), [&](std::ostream& stream) {
    stream << "  compiler::CodeAssembler ca_(state_);\n";

    DCHECK(!signature.return_type->IsVoidOrNever());

    assembler_ = CfgAssembler(Stack<const Type*>{});

    VisitResult expression_result = Visit(decl->body());
    VisitResult return_result =
        GenerateImplicitConvert(signature.return_type, expression_result);

    CSAGenerator csa_generator{assembler().Result(), stream};
    Stack<std::string> values = *csa_generator.EmitGraph(Stack<std::string>{});

    assembler_ = std::nullopt;

    stream << "  return ";
    CSAGenerator::EmitCSAValue(return_result, values, stream);
    stream << ";";
  });
}

void ImplementationVisitor::Visit(TypeAlias* alias) {
  if (alias->IsRedeclaration()) return;
  if (const ClassType* class_type = ClassType::DynamicCast(alias->type())) {
    if (class_type->IsExtern() && !class_type->nspace()->IsDefaultNamespace()) {
      Error(
          "extern classes are currently only supported in the default "
          "namespace");
    }
  }
}

class ImplementationVisitor::MacroInliningScope {
 public:
  MacroInliningScope(ImplementationVisitor* visitor, const Macro* macro)
      : visitor_(visitor), macro_(macro) {
    if (!visitor_->inlining_macros_.insert(macro).second) {
      // Recursive macro expansion would just keep going until stack overflow.
      // To avoid crashes, throw an error immediately.
      ReportError("Recursive macro call to ", *macro);
    }
  }
  ~MacroInliningScope() { visitor_->inlining_macros_.erase(macro_); }

 private:
  ImplementationVisitor* visitor_;
  const Macro* macro_;
};

VisitResult ImplementationVisitor::InlineMacro(
    Macro* macro, std::optional<LocationReference> this_reference,
    const std::vector<VisitResult>& arguments,
    const std::vector<Block*> label_blocks) {
  MacroInliningScope macro_inlining_scope(this, macro);
  CurrentScope::Scope current_scope(macro);
  BindingsManagersScope bindings_managers_scope;
  CurrentCallable::Scope current_callable(macro);
  CurrentReturnValue::Scope current_return_value;
  const Signature& signature = macro->signature();
  const Type* return_type = macro->signature().return_type;
  bool can_return = return_type != TypeOracle::GetNeverType();

  BlockBindings<LocalValue> parameter_bindings(&ValueBindingsManager::Get());
  BlockBindings<LocalLabel> label_bindings(&LabelBindingsManager::Get());
  DCHECK_EQ(macro->signature().parameter_names.size(),
            arguments.size() + (this_reference ? 1 : 0));
  DCHECK_EQ(this_reference.has_value(), macro->IsMethod());

  // Bind the this for methods. Methods that modify a struct-type "this" must
  // only be called if the this is in a variable, in which case the
  // LocalValue is non-const. Otherwise, the LocalValue used for the parameter
  // binding is const, and thus read-only, which will cause errors if
  // modified, e.g. when called by a struct method that sets the structs
  // fields. This prevents using temporary struct values for anything other
  // than read operations.
  if (this_reference) {
    DCHECK(macro->IsMethod());
    parameter_bindings.Add(kThisParameterName, LocalValue{*this_reference},
                           true);
    // TODO(v8:12261): Tracking 'this'-binding for kythe led to a few weird
    // issues. Review to fully support 'this' in methods.
  }

  size_t count = 0;
  for (const auto& arg : arguments) {
    if (this_reference && count == signature.implicit_count) count++;
    const bool mark_as_used = signature.implicit_count > count;
    const Identifier* name = macro->parameter_names()[count++];
    Binding<LocalValue>* binding =
        parameter_bindings.Add(name,
                               LocalValue{LocationReference::Temporary(
                                   arg, "parameter " + name->value)},
                               mark_as_used);
    if (GlobalContext::collect_kythe_data()) {
      KytheData::AddBindingDefinition(binding);
    }
  }

  DCHECK_EQ(label_blocks.size(), signature.labels.size());
  for (size_t i = 0; i < signature.labels.size(); ++i) {
    const LabelDeclaration& label_info = signature.labels[i];
    Binding<LocalLabel>* binding = label_bindings.Add(
        label_info.name, LocalLabel{label_blocks[i], label_info.types});
    if (GlobalContext::collect_kythe_data()) {
      KytheData::AddBindingDefinition(binding);
    }
  }

  Block* macro_end;
  std::optional<Binding<LocalLabel>> macro_end_binding;
  if (can_return) {
    Stack<const Type*> stack = assembler().CurrentStack();
    std::vector<const Type*> lowered_return_types = LowerType(return_type);
    stack.PushMany(lowered_return_types);
    if (!return_type->IsConstexpr()) {
      SetReturnValue(VisitResult(return_type,
                                 stack.TopRange(lowered_return_types.size())));
    }
    // The stack copy used to initialize the _macro_end block is only used
    // as a template for the actual gotos generated by return statements. It
    // doesn't correspond to any real return values, and thus shouldn't contain
    // top types, because these would pollute actual return value types that get
    // unioned with them for return statements, erroneously forcing them to top.
    for (auto i = stack.begin(); i != stack.end(); ++i) {
      if ((*i)->IsTopType()) {
        *i = TopType::cast(*i)->source_type();
      }
    }
    macro_end = assembler().NewBlock(std::move(stack));
    macro_end_binding.emplace(&LabelBindingsManager::Get(), kMacroEndLabelName,
                              LocalLabel{macro_end, {return_type}});
  } else {
    SetReturnValue(VisitResult::NeverResult());
  }

  const Type* result = Visit(*macro->body());

  if (result->IsNever()) {
    if (!return_type->IsNever() && !macro->HasReturns()) {
      std::stringstream s;
      s << "macro " << macro->ReadableName()
        << " that never returns must have return type never";
      ReportError(s.str());
    }
  } else {
    if (return_type->IsNever()) {
      std::stringstream s;
      s << "macro " << macro->ReadableName()
        << " has implicit return at end of its declartion but return type "
           "never";
      ReportError(s.str());
    } else if (!macro->signature().return_type->IsVoid()) {
      std::stringstream s;
      s << "macro " << macro->ReadableName()
        << " expects to return a value but doesn't on all paths";
      ReportError(s.str());
    }
  }
  if (!result->IsNever()) {
    assembler().Goto(macro_end);
  }

  if (macro->HasReturns() || !result->IsNever()) {
    assembler().Bind(macro_end);
  }

  return GetAndClearReturnValue();
}

void ImplementationVisitor::VisitMacroCommon(Macro* macro) {
  CurrentCallable::Scope current_callable(macro);
  const Signature& signature = macro->signature();
  const Type* return_type = macro->signature().return_type;
  bool can_return = return_type != TypeOracle::GetNeverType();
  bool has_return_value =
      can_return && return_type != TypeOracle::GetVoidType();

  cpp::Function f = GenerateMacroFunctionDeclaration(macro);
  f.PrintDeclaration(csa_headerfile());
  csa_headerfile() << "\n";

  cpp::File csa_cc(csa_ccfile());

  // Avoid multiple-definition errors since it is possible for multiple
  // generated -inl.inc files to all contain function definitions for the same
  // Torque macro.
  std::optional<cpp::IncludeGuardScope> include_guard;
  if (output_type_ == OutputType::kCC) {
    include_guard.emplace(&csa_cc, "V8_INTERNAL_DEFINED_"s + macro->CCName());
  } else if (output_type_ == OutputType::kCCDebug) {
    include_guard.emplace(&csa_cc,
                          "V8_INTERNAL_DEFINED_"s + macro->CCDebugName());
  }

  f.PrintBeginDefinition(csa_ccfile());

  if (output_type_ == OutputType::kCC) {
    // For now, generated C++ is only for field offset computations. If we ever
    // generate C++ code that can allocate, then it should be handlified.
    csa_ccfile() << "  DisallowGarbageCollection no_gc;\n";
  } else if (output_type_ == OutputType::kCSA) {
    csa_ccfile() << "  compiler::CodeAssembler ca_(state_);\n";
    csa_ccfile()
        << "  compiler::CodeAssembler::SourcePositionScope pos_scope(&ca_);\n";
  }

  Stack<std::string> lowered_parameters;
  Stack<const Type*> lowered_parameter_types;

  std::vector<VisitResult> arguments;

  std::optional<LocationReference> this_reference;
  if (Method* method = Method::DynamicCast(macro)) {
    const Type* this_type = method->aggregate_type();
    LowerParameter(this_type, ExternalParameterName(kThisParameterName),
                   &lowered_parameters);
    StackRange range = lowered_parameter_types.PushMany(LowerType(this_type));
    VisitResult this_result = VisitResult(this_type, range);
    // For classes, mark 'this' as a temporary to prevent assignment to it.
    // Note that using a VariableAccess for non-class types is technically
    // incorrect because changes to the 'this' variable do not get reflected
    // to the caller. Therefore struct methods should always be inlined and a
    // C++ version should never be generated, since it would be incorrect.
    // However, in order to be able to type- and semantics-check even unused
    // struct methods, set the this_reference to be the local variable copy of
    // the passed-in this, which allows the visitor to at least find and report
    // errors.
    this_reference =
        (this_type->IsClassType())
            ? LocationReference::Temporary(this_result, "this parameter")
            : LocationReference::VariableAccess(this_result);
  }

  for (size_t i = 0; i < macro->signature().parameter_names.size(); ++i) {
    if (this_reference && i == macro->signature().implicit_count) continue;
    const std::string& name = macro->parameter_names()[i]->value;
    std::string external_name = ExternalParameterName(name);
    const Type* type = macro->signature().types()[i];

    if (type->IsConstexpr()) {
      arguments.push_back(VisitResult(type, external_name));
    } else {
      LowerParameter(type, external_name, &lowered_parameters);
      StackRange range = lowered_parameter_types.PushMany(LowerType(type));
      arguments.push_back(VisitResult(type, range));
    }
  }

  DCHECK_EQ(lowered_parameters.Size(), lowered_parameter_types.Size());
  assembler_ = CfgAssembler(lowered_parameter_types);

  std::vector<Block*> label_blocks;
  for (const LabelDeclaration& label_info : signature.labels) {
    Stack<const Type*> label_input_stack;
    for (const Type* type : label_info.types) {
      label_input_stack.PushMany(LowerType(type));
    }
    Block* block = assembler().NewBlock(std::move(label_input_stack));
    label_blocks.push_back(block);
  }

  VisitResult return_value =
      InlineMacro(macro, this_reference, arguments, label_blocks);
  Block* end = assembler().NewBlock();
  if (return_type != TypeOracle::GetNeverType()) {
    assembler().Goto(end);
  }

  for (size_t i = 0; i < label_blocks.size(); ++i) {
    Block* label_block = label_blocks[i];
    const LabelDeclaration& label_info = signature.labels[i];
    assembler().Bind(label_block);
    std::vector<std::string> label_parameter_variables;
    for (size_t j = 0; j < label_info.types.size(); ++j) {
      LowerLabelParameter(label_info.types[j],
                          ExternalLabelParameterName(label_info.name->value, j),
                          &label_parameter_variables);
    }
    assembler().Emit(
        GotoExternalInstruction{ExternalLabelName(label_info.name->value),
                                std::move(label_parameter_variables)});
  }

  if (return_type != TypeOracle::GetNeverType()) {
    assembler().Bind(end);
  }

  std::optional<Stack<std::string>> values;
  if (output_type_ == OutputType::kCC) {
    CCGenerator cc_generator{assembler().Result(), csa_ccfile()};
    values = cc_generator.EmitGraph(lowered_parameters);
  } else if (output_type_ == OutputType::kCCDebug) {
    CCGenerator cc_generator{assembler().Result(), csa_ccfile(), true};
    values = cc_generator.EmitGraph(lowered_parameters);
  } else {
    CSAGenerator csa_generator{assembler().Result(), csa_ccfile()};
    values = csa_generator.EmitGraph(lowered_parameters);
  }

  assembler_ = std::nullopt;

  if (has_return_value) {
    csa_ccfile() << "  return ";
    if (output_type_ == OutputType::kCCDebug) {
      csa_ccfile() << "{d::MemoryAccessResult::kOk, ";
      CCGenerator::EmitCCValue(return_value, *values, csa_ccfile());
      csa_ccfile() << "}";
    } else if (output_type_ == OutputType::kCC) {
      CCGenerator::EmitCCValue(return_value, *values, csa_ccfile());
    } else {
      CSAGenerator::EmitCSAValue(return_value, *values, csa_ccfile());
    }
    csa_ccfile() << ";\n";
  }
  f.PrintEndDefinition(csa_ccfile());

  include_guard.reset();
}

void ImplementationVisitor::Visit(TorqueMacro* macro) {
  VisitMacroCommon(macro);
}

void ImplementationVisitor::Visit(Method* method) {
  DCHECK(!method->IsExternal());
  VisitMacroCommon(method);
}

namespace {

std::string AddParameter(size_t i, Builtin* builtin,
                         Stack<std::string>* parameters,
                         Stack<const Type*>* parameter_types,
                         BlockBindings<LocalValue>* parameter_bindings,
                         bool mark_as_used) {
  const Identifier* name = builtin->signature().parameter_names[i];
  const Type* type = builtin->signature().types()[i];
  std::string external_name = "parameter" + std::to_string(i);
  parameters->Push(external_name);
  StackRange range = parameter_types->PushMany(LowerType(type));
  Binding<LocalValue>* binding = parameter_bindings->Add(
      name,
      LocalValue{LocationReference::Temporary(VisitResult(type, range),
                                              "parameter " + name->value)},
      mark_as_used);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddBindingDefinition(binding);
  }
  return external_name;
}

}  // namespace

void ImplementationVisitor::Visit(Builtin* builtin) {
  if (builtin->IsExternal()) return;
  CurrentScope::Scope current_scope(builtin);
  CurrentCallable::Scope current_callable(builtin);
  CurrentReturnValue::Scope current_return_value;

  const std::string& name = builtin->ExternalName();
  const Signature& signature = builtin->signature();
  csa_ccfile() << "TF_BUILTIN(" << name << ", CodeStubAssembler) {\n"
               << "  compiler::CodeAssemblerState* state_ = state();"
               << "  compiler::CodeAssembler ca_(state());\n";

  Stack<const Type*> parameter_types;
  Stack<std::string> parameters;

  BindingsManagersScope bindings_managers_scope;

  BlockBindings<LocalValue> parameter_bindings(&ValueBindingsManager::Get());

  if (builtin->IsVarArgsJavaScript() || builtin->IsFixedArgsJavaScript()) {
    if (builtin->IsVarArgsJavaScript()) {
      DCHECK(signature.parameter_types.var_args);
      if (signature.ExplicitCount() > 0) {
        Error("Cannot mix explicit parameters with varargs.")
            .Position(signature.parameter_names[signature.implicit_count]->pos);
      }

      csa_ccfile() << "  TNode<Word32T> argc = UncheckedParameter<Word32T>("
                   << "Descriptor::kJSActualArgumentsCount);\n";
      csa_ccfile() << "  TNode<IntPtrT> "
                      "arguments_length(ChangeInt32ToIntPtr(UncheckedCast<"
                      "Int32T>(argc)));\n";
      csa_ccfile() << "  TNode<RawPtrT> arguments_frame = "
                      "UncheckedCast<RawPtrT>(LoadFramePointer());\n";
      csa_ccfile()
          << "  TorqueStructArguments "
             "torque_arguments(GetFrameArguments(arguments_frame, "
             "arguments_length, FrameArgumentsArgcType::kCountIncludesReceiver"
          << "));\n";
      csa_ccfile()
          << "  CodeStubArguments arguments(this, torque_arguments);\n";

      parameters.Push("torque_arguments.frame");
      parameters.Push("torque_arguments.base");
      parameters.Push("torque_arguments.length");
      parameters.Push("torque_arguments.actual_count");
      const Type* arguments_type = TypeOracle::GetArgumentsType();
      StackRange range = parameter_types.PushMany(LowerType(arguments_type));
      parameter_bindings.Add(*signature.arguments_variable,
                             LocalValue{LocationReference::Temporary(
                                 VisitResult(arguments_type, range),
                                 "parameter " + *signature.arguments_variable)},
                             true);
    }

    for (size_t i = 0; i < signature.implicit_count; ++i) {
      const std::string& param_name = signature.parameter_names[i]->value;
      SourcePosition param_pos = signature.parameter_names[i]->pos;
      std::string generated_name = AddParameter(
          i, builtin, &parameters, &parameter_types, &parameter_bindings, true);
      const Type* actual_type = signature.parameter_types.types[i];
      std::vector<const Type*> expected_types;
      if (param_name == "context") {
        csa_ccfile() << "  TNode<NativeContext> " << generated_name
                     << " = UncheckedParameter<NativeContext>("
                     << "Descriptor::kContext);\n";
        csa_ccfile() << "  USE(" << generated_name << ");\n";
        expected_types = {TypeOracle::GetNativeContextType(),
                          TypeOracle::GetContextType()};
      } else if (param_name == "receiver") {
        csa_ccfile()
            << "  TNode<Object> " << generated_name << " = "
            << (builtin->IsVarArgsJavaScript()
                    ? "arguments.GetReceiver()"
                    : "UncheckedParameter<Object>(Descriptor::kReceiver)")
            << ";\n";
        csa_ccfile() << "  USE(" << generated_name << ");\n";
        expected_types = {TypeOracle::GetJSAnyType()};
      } else if (param_name == "newTarget") {
        csa_ccfile() << "  TNode<Object> " << generated_name
                     << " = UncheckedParameter<Object>("
                     << "Descriptor::kJSNewTarget);\n";
        csa_ccfile() << "USE(" << generated_name << ");\n";
        expected_types = {TypeOracle::GetJSAnyType()};
      } else if (param_name == "target") {
        csa_ccfile() << "  TNode<JSFunction> " << generated_name
                     << " = UncheckedParameter<JSFunction>("
                     << "Descriptor::kJSTarget);\n";
        csa_ccfile() << "USE(" << generated_name << ");\n";
        expected_types = {TypeOracle::GetJSFunctionType()};
      } else if (param_name == "dispatchHandle") {
        if (V8_ENABLE_LEAPTIERING_BOOL) {
          csa_ccfile() << "  TNode<JSDispatchHandleT> " << generated_name
                       << " = "
                          "UncheckedParameter<JSDispatchHandleT>(Descriptor::"
                          "kJSDispatchHandle);\n";
        } else {
          csa_ccfile() << "  TNode<JSDispatchHandleT> " << generated_name
                       << " = InvalidDispatchHandleConstant();\n";
        }
        csa_ccfile() << "USE(" << generated_name << ");\n";
        expected_types = {TypeOracle::GetDispatchHandleType()};
      } else {
        Error(
            "Unexpected implicit parameter \"", param_name,
            "\" for JavaScript calling convention, "
            "expected \"context\", \"receiver\", \"target\", or \"newTarget\"")
            .Position(param_pos);
        expected_types = {actual_type};
      }
      if (std::find(expected_types.begin(), expected_types.end(),
                    actual_type) == expected_types.end()) {
        Error("According to JavaScript calling convention, expected parameter ",
              param_name, " to have type ", PrintList(expected_types, " or "),
              " but found type ", *actual_type)
            .Position(param_pos);
      }
    }

    for (size_t i = signature.implicit_count;
         i < signature.parameter_names.size(); ++i) {
      const std::string& parameter_name = signature.parameter_names[i]->value;
      const Type* type = signature.types()[i];
      const bool mark_as_used = signature.implicit_count > i;
      std::string var = AddParameter(i, builtin, &parameters, &parameter_types,
                                     &parameter_bindings, mark_as_used);
      csa_ccfile() << "  " << type->GetGeneratedTypeName() << " " << var
                   << " = "
                   << "UncheckedParameter<" << type->GetGeneratedTNodeTypeName()
                   << ">(Descriptor::k" << CamelifyString(parameter_name)
                   << ");\n";
      csa_ccfile() << "  USE(" << var << ");\n";
    }

  } else {
    DCHECK(builtin->IsStub());

    for (size_t i = 0; i < signature.parameter_names.size(); ++i) {
      const std::string& parameter_name = signature.parameter_names[i]->value;
      const Type* type = signature.types()[i];
      const bool mark_as_used = signature.implicit_count > i;
      std::string var = AddParameter(i, builtin, &parameters, &parameter_types,
                                     &parameter_bindings, mark_as_used);
      csa_ccfile() << "  " << type->GetGeneratedTypeName() << " " << var
                   << " = "
                   << "UncheckedParameter<" << type->GetGeneratedTNodeTypeName()
                   << ">(Descriptor::k" << CamelifyString(parameter_name)
                   << ");\n";
      csa_ccfile() << "  USE(" << var << ");\n";
    }
  }

  if (builtin->use_counter_name()) {
    DCHECK(!signature.parameter_types.types.empty());
    DCHECK(signature.parameter_types.types[0] ==
               TypeOracle::GetNativeContextType() ||
           signature.parameter_types.types[0] == TypeOracle::GetContextType());
    csa_ccfile() << "  CodeStubAssembler(state_).CallRuntime("
                 << "Runtime::kIncrementUseCounter, parameter0, "
                 << "CodeStubAssembler(state_).SmiConstant("
                 << *builtin->use_counter_name() << "));\n";
  }

  assembler_ = CfgAssembler(parameter_types);
  const Type* body_result = Visit(*builtin->body());
  if (body_result != TypeOracle::GetNeverType()) {
    ReportError("control reaches end of builtin, expected return of a value");
  }
  CSAGenerator csa_generator{assembler().Result(), csa_ccfile(),
                             builtin->kind()};
  csa_generator.EmitGraph(parameters);
  assembler_ = std::nullopt;
  csa_ccfile() << "}\n\n";
}

const Type* ImplementationVisitor::Visit(VarDeclarationStatement* stmt) {
  BlockBindings<LocalValue> block_bindings(&ValueBindingsManager::Get());
  return Visit(stmt, &block_bindings);
}

const Type* ImplementationVisitor::Visit(
    VarDeclarationStatement* stmt, BlockBindings<LocalValue>* block_bindings) {
  // const qualified variables are required to be initialized properly.
  if (stmt->const_qualified && !stmt->initializer) {
    ReportError("local constant \"", stmt->name, "\" is not initialized.");
  }

  std::optional<const Type*> type;
  if (stmt->type) {
    type = TypeVisitor::ComputeType(*stmt->type);
  }
  std::optional<VisitResult> init_result;
  if (stmt->initializer) {
    StackScope scope(this);
    init_result = Visit(*stmt->initializer);
    if (type) {
      init_result = GenerateImplicitConvert(*type, *init_result);
    }
    type = init_result->type();
    if ((*type)->IsConstexpr() && !stmt->const_qualified) {
      Error("Use 'const' instead of 'let' for variable '", stmt->name->value,
            "' of constexpr type '", (*type)->ToString(), "'.")
          .Position(stmt->name->pos)
          .Throw();
    }
    init_result = scope.Yield(*init_result);
  } else {
    DCHECK(type.has_value());
    if ((*type)->IsConstexpr()) {
      ReportError("constexpr variables need an initializer");
    }
    TypeVector lowered_types = LowerType(*type);
    for (const Type* t : lowered_types) {
      assembler().Emit(PushUninitializedInstruction{TypeOracle::GetTopType(
          "uninitialized variable '" + stmt->name->value + "' of type " +
              t->ToString() + " originally defined at " +
              PositionAsString(stmt->pos),
          t)});
    }
    init_result =
        VisitResult(*type, assembler().TopRange(lowered_types.size()));
  }
  LocationReference ref = stmt->const_qualified
                              ? LocationReference::Temporary(
                                    *init_result, "const " + stmt->name->value)
                              : LocationReference::VariableAccess(*init_result);
  block_bindings->Add(stmt->name, LocalValue{std::move(ref)});
  return TypeOracle::GetVoidType();
}

const Type* ImplementationVisitor::Visit(TailCallStatement* stmt) {
  return Visit(stmt->call, true).type();
}

Vis
"""


```