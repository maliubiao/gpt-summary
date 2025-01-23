Response: Let's break down the thought process for analyzing this C++ code and explaining its function and relation to JavaScript.

1. **Understand the Context:** The first line, `// Copyright 2017 the V8 project authors. All rights reserved.`, immediately tells us this code is part of the V8 JavaScript engine. The file path `v8/src/torque/declaration-visitor.cc` suggests it's related to "Torque," a language used within V8, and deals with "declarations."  The `.cc` extension signifies C++ code.

2. **Identify Key Classes and Concepts:**  Skimming through the code reveals important names: `DeclarationVisitor`, `PredeclarationVisitor`, `Builtin`, `Macro`, `RuntimeFunction`, `GenericCallable`, `TypeAlias`, `Namespace`, `Signature`, `TypeOracle`. These are central to understanding the code's purpose. It appears to be processing declarations in the Torque language.

3. **Analyze the `PredeclarationVisitor`:** This visitor seems to handle an initial pass over declarations. The `Predeclare` function switches on the `decl->kind` and calls specific handlers for `NamespaceDeclaration`, `GenericCallableDeclaration`, and `GenericTypeDeclaration`. The comment "Only processes type declaration nodes, namespaces and generics" is crucial. This suggests a two-pass process where essential structural elements are handled first.

4. **Analyze the `DeclarationVisitor`:**  This visitor seems to be the main worker. The `Visit` function similarly switches on `decl->kind` but handles a broader range of declarations (indicated by `AST_DECLARATION_NODE_KIND_LIST`). The presence of specific `Visit` methods for different declaration types (e.g., `Visit(ExternalBuiltinDeclaration*)`, `Visit(TorqueBuiltinDeclaration*)`) reinforces this.

5. **Focus on Core Functionality within `DeclarationVisitor`:**  Several methods stand out:
    * `CreateBuiltin`: This function is clearly responsible for creating `Builtin` objects. It takes various parameters related to the builtin's signature, linkage (JavaScript or not), and other properties. The logic within this function performs validation (e.g., return type for JavaScript builtins).
    * `Visit` methods for various declaration types: These methods handle the creation and registration of different Torque entities (Builtins, Macros, Runtime Functions, etc.) based on the parsed declarations. They often use `Declarations::Declare...` functions, implying a central registry.
    * `Specialize` and `SpecializeImplicit`: These functions are involved in handling generic callables and creating specialized versions based on concrete type arguments. This is a powerful feature for code reuse and optimization.
    * `MakeSpecializedSignature`:  This helps determine the signature of a specialized callable.
    * `ResolvePredeclarations`: This function in `PredeclarationVisitor` is called after the initial pass to resolve type aliases.

6. **Connect to JavaScript:**  The key connection lies in the handling of `Builtin` declarations, especially those with `javascript_linkage`. The code explicitly checks for this flag and enforces constraints related to JavaScript types (like `JSAny`). The comments within `CreateBuiltin` regarding parameter types and the need for `JSAny` for JavaScript-linked builtins are strong indicators of this connection.

7. **Formulate the Summary:** Based on the analysis, the primary function of `declaration-visitor.cc` is to process Torque language declarations and create corresponding internal representations within the V8 engine. It's a crucial step in the Torque compilation process.

8. **Construct the JavaScript Example:** To illustrate the connection, think about how built-in JavaScript functions are implemented. Functions like `Array.push`, `String.charCodeAt`, or `console.log` are essentially "builtins."  The Torque code likely defines the *interface* and some of the *implementation details* for these builtins. The C++ code generated from Torque then interacts with the core JavaScript runtime. The example should showcase a simple JavaScript function and then speculate how it *might* be represented in Torque, emphasizing the type information and potential internal implementation details.

9. **Refine and Organize:**  Structure the explanation logically. Start with a general summary, then detail the functions of the two visitors. Highlight the `CreateBuiltin` function and its JavaScript connection. Finally, provide the JavaScript example and explain how it relates back to the C++ code. Use clear and concise language, avoiding overly technical jargon where possible.

Self-Correction/Refinement during the process:

* **Initial thought:**  Maybe it just parses the Torque code. **Correction:**  It's more than just parsing; it's creating internal representations (`Builtin`, `Macro`, etc.) and performing validation.
* **Focusing too much on details:**  Don't get bogged down in every single line of code. Focus on the main functions and their purpose.
* **Not making the JavaScript connection clear enough:**  Emphasize the `javascript_linkage` flag and the type constraints. The example needs to be simple and illustrative.
* **Using precise terminology:** Refer to "Torque" and "V8" explicitly to maintain accuracy.

By following this thought process, breaking down the code into manageable parts, and focusing on the key functionalities and connections, one can arrive at a comprehensive and understandable explanation of the provided C++ code.
这个C++源代码文件 `declaration-visitor.cc` 的主要功能是**遍历 Torque 语言的抽象语法树 (AST)，并根据遇到的声明节点创建相应的内部表示（Declarable）**。 Torque 是 V8 JavaScript 引擎使用的一种领域特定语言 (DSL)，用于定义 JavaScript 内置函数和运行时函数的行为。

更具体地说，`declaration-visitor.cc` 实现了两个主要的访问者类：

* **`PredeclarationVisitor`**:  这个访问者执行一个预声明的阶段，主要处理命名空间、泛型类型和泛型函数的声明。它的目的是在主声明阶段之前，先注册这些顶层结构，以便后续的声明可以正确地引用它们。
* **`DeclarationVisitor`**: 这是主要的访问者类，负责处理所有类型的声明节点。它根据声明的类型创建不同的 `Declarable` 对象，例如：
    * **内置函数 (Builtin)**: 包括 Torque 定义的内置函数和外部 C++ 定义的内置函数。
    * **宏 (Macro)**:  类似于内置函数，但通常更小更内联。
    * **运行时函数 (RuntimeFunction)**:  V8 运行时系统中用 C++ 实现的函数。
    * **常量 (Const/ExternConst)**:  在 Torque 中定义的常量。
    * **类型别名 (TypeAlias)**:  为类型定义新的名称。
    * **命名空间 (Namespace)**:  组织代码的逻辑分组。
    * **泛型声明 (GenericCallableDeclaration/GenericTypeDeclaration)**:  允许定义可以接受类型参数的函数和类型。
    * **特化 (SpecializationDeclaration)**:  为泛型函数或类型提供具体的类型参数。

**与 JavaScript 的关系以及 JavaScript 例子:**

`declaration-visitor.cc` 的核心作用是为 JavaScript 的内置功能奠定基础。Torque 代码描述了这些内置函数的签名、类型以及可能的实现逻辑（对于 Torque 定义的内置函数）。 这些 Torque 代码最终会被编译成 C++ 代码，并集成到 V8 引擎中，从而实现 JavaScript 的功能。

**JavaScript 例子:**

假设在 Torque 中有如下的 (简化的) 内置函数声明，用于实现 JavaScript 的 `Array.prototype.push` 方法：

```torque
// 假设的 Torque 代码 (简化)
builtin ArrayPush<T>(implicit context: NativeContext, receiver: JSReceiver, ...elements: T): Number {
  // ... 一些 Torque 代码来操作 receiver (Array 对象) 并添加 elements ...
  return numberOfElementsAfterPush;
}
```

这个 Torque 代码声明了一个名为 `ArrayPush` 的内置函数，它：

* 是一个泛型函数，可以处理不同类型的元素 `T`。
* 接收一个隐式的 `context` 参数 (V8 内部上下文)。
* 接收一个 `receiver` 参数，它应该是一个 `JSReceiver` (通常是 Array 对象)。
* 接收可变数量的 `elements`，类型为 `T`。
* 返回一个 `Number`，表示 `push` 操作后数组的元素个数。

`declaration-visitor.cc` 的作用就是在解析到这个 Torque 声明时，会创建一个 `Builtin` 对象，记录下 `ArrayPush` 的名称、参数类型、返回值类型等信息。  它还会处理泛型参数 `T`，并可能在遇到 `ArrayPush` 的具体特化（例如 `ArrayPush<Int32>` 或 `ArrayPush<String>`) 时创建相应的特化版本。

**在 JavaScript 中使用 `Array.prototype.push`:**

```javascript
const myArray = [1, 2, 3];
const newLength = myArray.push(4, 5);
console.log(myArray); // 输出: [1, 2, 3, 4, 5]
console.log(newLength); // 输出: 5
```

当 JavaScript 引擎执行 `myArray.push(4, 5)` 时，V8 内部会查找与 `Array.prototype.push` 对应的内置函数实现。  这个实现很可能就是由之前提到的 Torque 代码（或者其编译后的 C++ 版本）提供的。

**总结:**

`declaration-visitor.cc` 是 Torque 编译过程中的一个关键组件，它负责将 Torque 源代码中的声明转换为 V8 引擎可以理解和使用的内部表示。 这些内部表示最终驱动着 JavaScript 内置功能的实现。  换句话说，Torque 代码定义了 JavaScript 的行为，而 `declaration-visitor.cc` 则负责理解和注册这些定义。

### 提示词
```
这是目录为v8/src/torque/declaration-visitor.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/declaration-visitor.h"

#include <optional>

#include "src/torque/ast.h"
#include "src/torque/kythe-data.h"
#include "src/torque/server-data.h"
#include "src/torque/type-inference.h"
#include "src/torque/type-visitor.h"

namespace v8::internal::torque {

Namespace* GetOrCreateNamespace(const std::string& name) {
  std::vector<Namespace*> existing_namespaces = FilterDeclarables<Namespace>(
      Declarations::TryLookupShallow(QualifiedName(name)));
  if (existing_namespaces.empty()) {
    return Declarations::DeclareNamespace(name);
  }
  DCHECK_EQ(1, existing_namespaces.size());
  return existing_namespaces.front();
}

void PredeclarationVisitor::Predeclare(Declaration* decl) {
  CurrentSourcePosition::Scope scope(decl->pos);
  switch (decl->kind) {
#define ENUM_ITEM(name)        \
  case AstNode::Kind::k##name: \
    return Predeclare(name::cast(decl));
    AST_TYPE_DECLARATION_NODE_KIND_LIST(ENUM_ITEM)
#undef ENUM_ITEM
    case AstNode::Kind::kNamespaceDeclaration:
      return Predeclare(NamespaceDeclaration::cast(decl));
    case AstNode::Kind::kGenericCallableDeclaration:
      return Predeclare(GenericCallableDeclaration::cast(decl));
    case AstNode::Kind::kGenericTypeDeclaration:
      return Predeclare(GenericTypeDeclaration::cast(decl));

    default:
      // Only processes type declaration nodes, namespaces and generics.
      break;
  }
}

void DeclarationVisitor::Visit(Declaration* decl) {
  CurrentSourcePosition::Scope scope(decl->pos);
  switch (decl->kind) {
#define ENUM_ITEM(name)        \
  case AstNode::Kind::k##name: \
    return Visit(name::cast(decl));
    AST_DECLARATION_NODE_KIND_LIST(ENUM_ITEM)
#undef ENUM_ITEM
    default:
      UNIMPLEMENTED();
  }
}

Builtin* DeclarationVisitor::CreateBuiltin(
    BuiltinDeclaration* decl, std::string external_name,
    std::string readable_name, Signature signature,
    std::optional<std::string> use_counter_name,
    std::optional<Statement*> body) {
  const bool javascript = decl->javascript_linkage;
  const bool varargs = decl->parameters.has_varargs;
  Builtin::Kind kind = !javascript ? Builtin::kStub
                                   : varargs ? Builtin::kVarArgsJavaScript
                                             : Builtin::kFixedArgsJavaScript;
  bool has_custom_interface_descriptor = false;
  if (decl->kind == AstNode::Kind::kTorqueBuiltinDeclaration) {
    has_custom_interface_descriptor =
        static_cast<TorqueBuiltinDeclaration*>(decl)
            ->has_custom_interface_descriptor;
  }

  if (varargs && !javascript) {
    Error("Rest parameters require ", decl->name,
          " to be a JavaScript builtin");
  }

  if (javascript) {
    if (!signature.return_type->IsSubtypeOf(TypeOracle::GetJSAnyType())) {
      Error("Return type of JavaScript-linkage builtins has to be JSAny.")
          .Position(decl->return_type->pos);
    }
    // Validate the parameter types. In general, for JS builtins the parameters
    // must all be tagged values (JSAny). However, we currently allow declaring
    // "extern javascript" builtins with any parameter types. The reason is
    // that those are typically used for tailcalls, in which case we typically
    // need to supply the implicit parameters of the JS calling convention
    // (target, receiver, argc, etc.). It would probablu be nicer if we could
    // instead declare these parameters as js-implicit (like we do for
    // torque-defined javascript builtins) and then allow explicitly supplying
    // the implicit arguments during tailscalls. It's unclear though if that's
    // worth the effort. In particular, calls and tailcalls to javascript
    // builtins will emit CSA::CallJSBuiltin and CSA::TailCallJSBuiltin calls
    // which will validate the parameter types at C++ compile time.
    if (decl->kind != AstNode::Kind::kExternalBuiltinDeclaration) {
      for (size_t i = signature.implicit_count;
           i < signature.parameter_types.types.size(); ++i) {
        const Type* parameter_type = signature.parameter_types.types[i];
        if (!TypeOracle::GetJSAnyType()->IsSubtypeOf(parameter_type)) {
          Error(
              "Parameters of JavaScript-linkage builtins have to be a "
              "supertype "
              "of JSAny.")
              .Position(decl->parameters.types[i]->pos);
        }
      }
    }
  }

  for (size_t i = 0; i < signature.types().size(); ++i) {
    const Type* parameter_type = signature.types()[i];
    if (parameter_type->StructSupertype()) {
      Error("Builtin do not support structs as arguments, but argument ",
            signature.parameter_names[i], " has type ", *signature.types()[i],
            ".");
    }
    if (parameter_type->IsFloat32() || parameter_type->IsFloat64()) {
      if (!has_custom_interface_descriptor) {
        Error("Builtin ", external_name,
              " needs a custom interface descriptor, "
              "because it uses type ",
              *parameter_type, " for argument ", signature.parameter_names[i],
              ". One reason being "
              "that the default descriptor defines xmm0 to be the first "
              "floating point argument register, which is current used as "
              "scratch on ia32 and cannot be allocated.");
      }
    }
  }

  if (signature.return_type->StructSupertype() && javascript) {
    Error(
        "Builtins with JS linkage cannot return structs, but the return type "
        "is ",
        *signature.return_type, ".");
  }

  if (signature.return_type == TypeOracle::GetVoidType()) {
    Error("Builtins cannot have return type void.");
  }

  Builtin::Flags flags = Builtin::Flag::kNone;
  if (has_custom_interface_descriptor)
    flags |= Builtin::Flag::kCustomInterfaceDescriptor;
  Builtin* builtin = Declarations::CreateBuiltin(
      std::move(external_name), std::move(readable_name), kind, flags,
      std::move(signature), std::move(use_counter_name), body);
  // TODO(v8:12261): Recheck this.
  // builtin->SetIdentifierPosition(decl->name->pos);
  return builtin;
}

void DeclarationVisitor::Visit(ExternalBuiltinDeclaration* decl) {
  Builtin* builtin = CreateBuiltin(decl, decl->name->value, decl->name->value,
                                   TypeVisitor::MakeSignature(decl),
                                   std::nullopt, std::nullopt);
  builtin->SetIdentifierPosition(decl->name->pos);
  Declarations::Declare(decl->name->value, builtin);
}

void DeclarationVisitor::Visit(ExternalRuntimeDeclaration* decl) {
  Signature signature = TypeVisitor::MakeSignature(decl);
  if (signature.parameter_types.types.empty()) {
    ReportError(
        "Missing parameters for runtime function, at least the context "
        "parameter is required.");
  }
  if (!(signature.parameter_types.types[0] == TypeOracle::GetContextType() ||
        signature.parameter_types.types[0] == TypeOracle::GetNoContextType())) {
    ReportError(
        "first parameter to runtime functions has to be the context and have "
        "type Context or NoContext, but found type ",
        *signature.parameter_types.types[0]);
  }
  if (!(signature.return_type->IsSubtypeOf(TypeOracle::GetStrongTaggedType()) ||
        signature.return_type == TypeOracle::GetVoidType() ||
        signature.return_type == TypeOracle::GetNeverType())) {
    ReportError(
        "runtime functions can only return strong tagged values, but "
        "found type ",
        *signature.return_type);
  }
  for (const Type* parameter_type : signature.parameter_types.types) {
    if (!parameter_type->IsSubtypeOf(TypeOracle::GetStrongTaggedType())) {
      ReportError(
          "runtime functions can only take strong tagged parameters, but "
          "found type ",
          *parameter_type);
    }
  }

  RuntimeFunction* function =
      Declarations::DeclareRuntimeFunction(decl->name->value, signature);
  function->SetIdentifierPosition(decl->name->pos);
  function->SetPosition(decl->pos);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddFunctionDefinition(function);
  }
}

void DeclarationVisitor::Visit(ExternalMacroDeclaration* decl) {
  Macro* macro = Declarations::DeclareMacro(
      decl->name->value, true, decl->external_assembler_name,
      TypeVisitor::MakeSignature(decl), std::nullopt, decl->op);
  macro->SetIdentifierPosition(decl->name->pos);
  macro->SetPosition(decl->pos);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddFunctionDefinition(macro);
  }
}

void DeclarationVisitor::Visit(TorqueBuiltinDeclaration* decl) {
  Signature signature = TypeVisitor::MakeSignature(decl);
  if (decl->use_counter_name &&
      (signature.types().empty() ||
       (signature.types()[0] != TypeOracle::GetNativeContextType() &&
        signature.types()[0] != TypeOracle::GetContextType()))) {
    ReportError(
        "@incrementUseCounter requires the builtin's first parameter to be of "
        "type Context or NativeContext, but found type ",
        *signature.types()[0]);
  }
  auto builtin = CreateBuiltin(decl, decl->name->value, decl->name->value,
                               signature, decl->use_counter_name, decl->body);
  builtin->SetIdentifierPosition(decl->name->pos);
  builtin->SetPosition(decl->pos);
  Declarations::Declare(decl->name->value, builtin);
}

void DeclarationVisitor::Visit(TorqueMacroDeclaration* decl) {
  Macro* macro = Declarations::DeclareMacro(
      decl->name->value, decl->export_to_csa, std::nullopt,
      TypeVisitor::MakeSignature(decl), decl->body, decl->op);
  macro->SetIdentifierPosition(decl->name->pos);
  macro->SetPosition(decl->pos);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddFunctionDefinition(macro);
  }
}

void DeclarationVisitor::Visit(IntrinsicDeclaration* decl) {
  Declarations::DeclareIntrinsic(decl->name->value,
                                 TypeVisitor::MakeSignature(decl));
}

void DeclarationVisitor::Visit(ConstDeclaration* decl) {
  auto constant = Declarations::DeclareNamespaceConstant(
      decl->name, TypeVisitor::ComputeType(decl->type), decl->expression);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddConstantDefinition(constant);
  }
}

void DeclarationVisitor::Visit(SpecializationDeclaration* decl) {
  std::vector<GenericCallable*> generic_list =
      Declarations::LookupGeneric(decl->name->value);
  // Find the matching generic specialization based on the concrete parameter
  // list.
  GenericCallable* matching_generic = nullptr;
  Signature signature_with_types = TypeVisitor::MakeSignature(decl);
  for (GenericCallable* generic : generic_list) {
    // This argument inference is just to trigger constraint checking on the
    // generic arguments.
    TypeArgumentInference inference = generic->InferSpecializationTypes(
        TypeVisitor::ComputeTypeVector(decl->generic_parameters), {});
    if (inference.HasFailed()) {
      continue;
    }
    Signature generic_signature_with_types =
        MakeSpecializedSignature(SpecializationKey<GenericCallable>{
            generic, TypeVisitor::ComputeTypeVector(decl->generic_parameters)});
    if (signature_with_types.HasSameTypesAs(generic_signature_with_types,
                                            ParameterMode::kIgnoreImplicit)) {
      if (matching_generic != nullptr) {
        std::stringstream stream;
        stream << "specialization of " << decl->name
               << " is ambigous, it matches more than one generic declaration ("
               << *matching_generic << " and " << *generic << ")";
        ReportError(stream.str());
      }
      matching_generic = generic;
    }
  }

  if (matching_generic == nullptr) {
    std::stringstream stream;
    if (generic_list.empty()) {
      stream << "no generic defined with the name " << decl->name;
      ReportError(stream.str());
    }
    stream << "specialization of " << decl->name
           << " doesn't match any generic declaration\n";
    stream << "specialization signature:";
    stream << "\n  " << signature_with_types;
    stream << "\ncandidates are:";
    for (GenericCallable* generic : generic_list) {
      stream << "\n  "
             << MakeSpecializedSignature(SpecializationKey<GenericCallable>{
                    generic,
                    TypeVisitor::ComputeTypeVector(decl->generic_parameters)});
    }
    ReportError(stream.str());
  }

  if (GlobalContext::collect_language_server_data()) {
    LanguageServerData::AddDefinition(decl->name->pos,
                                      matching_generic->IdentifierPosition());
  }

  CallableDeclaration* generic_declaration = matching_generic->declaration();

  Specialize(SpecializationKey<GenericCallable>{matching_generic,
                                                TypeVisitor::ComputeTypeVector(
                                                    decl->generic_parameters)},
             generic_declaration, decl, decl->body, decl->pos);
}

void DeclarationVisitor::Visit(ExternConstDeclaration* decl) {
  const Type* type = TypeVisitor::ComputeType(decl->type);
  if (!type->IsConstexpr()) {
    std::stringstream stream;
    stream << "extern constants must have constexpr type, but found: \""
           << *type << "\"\n";
    ReportError(stream.str());
  }

  ExternConstant* constant =
      Declarations::DeclareExternConstant(decl->name, type, decl->literal);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddConstantDefinition(constant);
  }
}

void DeclarationVisitor::Visit(CppIncludeDeclaration* decl) {
  GlobalContext::AddCppInclude(decl->include_path);
}

void DeclarationVisitor::DeclareSpecializedTypes(
    const SpecializationKey<GenericCallable>& key) {
  size_t i = 0;
  const std::size_t generic_parameter_count =
      key.generic->generic_parameters().size();
  if (generic_parameter_count != key.specialized_types.size()) {
    std::stringstream stream;
    stream << "Wrong generic argument count for specialization of \""
           << key.generic->name() << "\", expected: " << generic_parameter_count
           << ", actual: " << key.specialized_types.size();
    ReportError(stream.str());
  }

  for (auto type : key.specialized_types) {
    Identifier* generic_type_name = key.generic->generic_parameters()[i++].name;
    TypeAlias* alias = Declarations::DeclareType(generic_type_name, type);
    alias->SetIsUserDefined(false);
  }
}

Signature DeclarationVisitor::MakeSpecializedSignature(
    const SpecializationKey<GenericCallable>& key) {
  CurrentScope::Scope generic_scope(key.generic->ParentScope());
  // Create a temporary fake-namespace just to temporarily declare the
  // specialization aliases for the generic types to create a signature.
  Namespace tmp_namespace("_tmp");
  CurrentScope::Scope tmp_namespace_scope(&tmp_namespace);
  DeclareSpecializedTypes(key);
  return TypeVisitor::MakeSignature(key.generic->declaration());
}

Callable* DeclarationVisitor::SpecializeImplicit(
    const SpecializationKey<GenericCallable>& key) {
  std::optional<Statement*> body = key.generic->CallableBody();
  if (!body && IntrinsicDeclaration::DynamicCast(key.generic->declaration()) ==
                   nullptr) {
    ReportError("missing specialization of ", key.generic->name(),
                " with types <", key.specialized_types, "> declared at ",
                key.generic->Position());
  }
  SpecializationRequester requester{CurrentSourcePosition::Get(),
                                    CurrentScope::Get(), ""};
  CurrentScope::Scope generic_scope(key.generic->ParentScope());
  Callable* result = Specialize(key, key.generic->declaration(), std::nullopt,
                                body, CurrentSourcePosition::Get());
  result->SetIsUserDefined(false);
  requester.name = result->ReadableName();
  result->SetSpecializationRequester(requester);
  CurrentScope::Scope callable_scope(result);
  DeclareSpecializedTypes(key);
  return result;
}

Callable* DeclarationVisitor::Specialize(
    const SpecializationKey<GenericCallable>& key,
    CallableDeclaration* declaration,
    std::optional<const SpecializationDeclaration*> explicit_specialization,
    std::optional<Statement*> body, SourcePosition position) {
  CurrentSourcePosition::Scope pos_scope(position);
  size_t generic_parameter_count = key.generic->generic_parameters().size();
  if (generic_parameter_count != key.specialized_types.size()) {
    std::stringstream stream;
    stream << "number of template parameters ("
           << std::to_string(key.specialized_types.size())
           << ") to intantiation of generic " << declaration->name
           << " doesnt match the generic's declaration ("
           << std::to_string(generic_parameter_count) << ")";
    ReportError(stream.str());
  }
  if (key.generic->GetSpecialization(key.specialized_types)) {
    ReportError("cannot redeclare specialization of ", key.generic->name(),
                " with types <", key.specialized_types, ">");
  }

  Signature type_signature =
      explicit_specialization
          ? TypeVisitor::MakeSignature(*explicit_specialization)
          : MakeSpecializedSignature(key);

  std::string generated_name = Declarations::GetGeneratedCallableName(
      declaration->name->value, key.specialized_types);
  std::stringstream readable_name;
  readable_name << declaration->name->value << "<";
  bool first = true;
  for (const Type* t : key.specialized_types) {
    if (!first) readable_name << ", ";
    readable_name << *t;
    first = false;
  }
  readable_name << ">";
  Callable* callable;
  if (MacroDeclaration::DynamicCast(declaration) != nullptr) {
    callable =
        Declarations::CreateTorqueMacro(generated_name, readable_name.str(),
                                        false, type_signature, *body, true);
  } else if (IntrinsicDeclaration::DynamicCast(declaration) != nullptr) {
    callable =
        Declarations::CreateIntrinsic(declaration->name->value, type_signature);
  } else {
    BuiltinDeclaration* builtin = BuiltinDeclaration::cast(declaration);
    std::optional<std::string> use_counter_name;
    if (TorqueBuiltinDeclaration* torque_builtin =
            TorqueBuiltinDeclaration::DynamicCast(builtin)) {
      use_counter_name = torque_builtin->use_counter_name;
    } else {
      use_counter_name = std::nullopt;
    }
    callable = CreateBuiltin(
        builtin, GlobalContext::MakeUniqueName(generated_name),
        readable_name.str(), type_signature, use_counter_name, *body);
  }
  key.generic->AddSpecialization(key.specialized_types, callable);
  return callable;
}

void PredeclarationVisitor::ResolvePredeclarations() {
  const auto& all_declarables = GlobalContext::AllDeclarables();
  for (size_t i = 0; i < all_declarables.size(); ++i) {
    Declarable* declarable = all_declarables[i].get();
    if (const TypeAlias* alias = TypeAlias::DynamicCast(declarable)) {
      CurrentScope::Scope scope_activator(alias->ParentScope());
      CurrentSourcePosition::Scope position_activator(alias->Position());
      alias->Resolve();
    }
  }
}

}  // namespace v8::internal::torque
```