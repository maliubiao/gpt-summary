Response:
Let's break down the thought process for analyzing the provided C++ code and fulfilling the request.

**1. Initial Understanding: What is the code doing?**

The code starts with a copyright notice and includes. This immediately signals a C++ file related to the V8 JavaScript engine, specifically within the `torque` component. The presence of includes like `ast.h`, `kythe-data.h`, `server-data.h`, `type-inference.h`, and `type-visitor.h` hints at a compiler-like functionality that processes some kind of input (likely the `.tq` files mentioned later). The names `DeclarationVisitor` and `PredeclarationVisitor` strongly suggest a process of iterating through and handling declarations within this input.

**2. Identifying Key Classes and Their Roles:**

Scanning through the code reveals crucial classes:

* **`DeclarationVisitor` and `PredeclarationVisitor`:** These are the central actors. The names suggest distinct phases of processing declarations. `PredeclarationVisitor` likely does some initial setup or gathering of information *before* full processing. `DeclarationVisitor` seems to perform the main actions for each declaration.
* **`Declaration` and its subclasses (e.g., `NamespaceDeclaration`, `BuiltinDeclaration`, `TorqueBuiltinDeclaration`, `MacroDeclaration`, etc.):** This indicates an Abstract Syntax Tree (AST) representation of the input language. Each subclass represents a different kind of declaration.
* **`TypeVisitor`:**  Clearly responsible for dealing with types and signatures. Functions like `MakeSignature` and `ComputeType` confirm this.
* **`Declarations`:**  Likely a central registry or manager for storing information about declared entities (namespaces, builtins, macros, etc.). Functions like `DeclareNamespace`, `CreateBuiltin`, `DeclareMacro` point to this.
* **`Builtin`, `Macro`, `RuntimeFunction`, `Namespace`, `TypeAlias`, `ExternConstant`, `Intrinsic`:** These are the core entities being declared and managed.
* **`Signature`:**  Represents the type information of a function or method (parameters and return type).
* **`TypeOracle`:** Likely a singleton or central point for accessing core type information (e.g., `GetJSAnyType`, `GetContextType`).
* **`SpecializationKey` and `Specialize`:**  These relate to generic programming, allowing special versions of functions/macros for specific types.

**3. Dissecting the Functionality of `DeclarationVisitor`:**

The `DeclarationVisitor::Visit(Declaration* decl)` function acts as a dispatcher, using a `switch` statement based on the `decl->kind` to call more specific `Visit` methods for each declaration type. This is a classic Visitor pattern. By examining these specific `Visit` methods, we can deduce the actions performed for each kind of declaration:

* **`Visit(ExternalBuiltinDeclaration*)`:** Creates a `Builtin` object, likely representing a built-in function implemented in C++.
* **`Visit(ExternalRuntimeDeclaration*)`:** Creates a `RuntimeFunction` object, representing a runtime function. It enforces parameter type constraints (context parameter).
* **`Visit(ExternalMacroDeclaration*)`:** Creates a `Macro` object, representing an external macro.
* **`Visit(TorqueBuiltinDeclaration*)`:** Creates a `Builtin` object for a Torque-defined builtin, with potential checks for `@incrementUseCounter`.
* **`Visit(TorqueMacroDeclaration*)`:** Creates a `Macro` object for a Torque-defined macro.
* **`Visit(IntrinsicDeclaration*)`:** Declares an intrinsic function.
* **`Visit(ConstDeclaration*)`:** Declares a constant within a namespace.
* **`Visit(SpecializationDeclaration*)`:** Handles specialization of generic callables. This is more complex, involving lookup, matching signatures, and creating specialized versions.
* **`Visit(ExternConstDeclaration*)`:** Declares an external constant.
* **`Visit(CppIncludeDeclaration*)`:** Adds a C++ include path.

**4. Dissecting the Functionality of `PredeclarationVisitor`:**

The `PredeclarationVisitor::Predeclare(Declaration* decl)` function also acts as a dispatcher, but it handles a smaller subset of declarations (primarily type declarations, namespaces, and generics). This suggests an initial pass to gather essential information about types and structures before processing the full details of other declarations. The `ResolvePredeclarations()` function confirms this by handling the resolution of `TypeAlias` objects.

**5. Connecting to `.tq` Files and JavaScript:**

The prompt explicitly mentions `.tq` files. The code processes declarations, and the types of declarations (builtins, macros) strongly suggest this code is part of the Torque compiler. Torque is V8's DSL for writing performance-critical built-in functions, often with a close relationship to JavaScript functionality.

**6. Providing JavaScript Examples (if applicable):**

Since Torque builtins and macros often correspond to JavaScript features, providing examples is crucial. The examples should illustrate the *JavaScript equivalent* of what the Torque code is defining. For instance, a Torque builtin might implement a core JavaScript method like `Array.prototype.push`.

**7. Identifying Potential Errors:**

The code includes error reporting (`Error`, `ReportError`). By examining these error messages and the conditions that trigger them, we can identify common programming mistakes when writing Torque code:

* Incorrect parameter types for JavaScript builtins.
* Incorrect return types for JavaScript builtins.
* Using structs as arguments for builtins.
* Missing `Context` or `NativeContext` parameters for builtins using `@incrementUseCounter`.
* Redeclaring specializations.
* Incorrect number of generic type arguments.
* Non-constexpr types for `extern const`.

**8. Developing Input/Output Examples (for logic):**

For more complex logic, like the `SpecializationDeclaration` handling, hypothetical inputs and outputs are helpful to illustrate the flow:

* **Input:** A `SpecializationDeclaration` with specific types.
* **Process:** The code looks up the corresponding generic, checks if the signature matches, and potentially creates a specialized version.
* **Output:**  The creation of a specialized `Builtin` or `Macro`.

**9. Structuring the Answer:**

Finally, the information needs to be organized logically, addressing each part of the prompt:

* Overall functionality.
* Connection to `.tq` files and Torque.
* Relationship to JavaScript (with examples).
* Code logic explanation (with input/output).
* Common programming errors (with examples).

This systematic approach, moving from high-level understanding to detailed analysis, and then connecting the code to its purpose and context, is key to effectively answering questions about complex software like the V8 engine.
`v8/src/torque/declaration-visitor.cc` 是 V8 JavaScript 引擎中 Torque 编译器的源代码文件。它的主要功能是**遍历 Torque 源代码的抽象语法树 (AST)，并处理各种声明语句，例如内置函数 (builtins)、宏 (macros)、类型别名 (type aliases)、常量 (constants) 等。**  它负责将 Torque 代码中声明的结构注册到 Torque 的声明管理系统中，以便在后续的编译阶段使用。

**如果 `v8/src/torque/declaration-visitor.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。** 但实际上，它是一个 C++ 文件，负责处理以 `.tq` 结尾的 Torque 源代码。

**它与 javascript 的功能有密切关系。** Torque 的主要目的是为 V8 引擎编写高性能的内置函数和运行时代码，这些代码直接在 JavaScript 虚拟机中执行。因此，`declaration-visitor.cc` 处理的声明直接对应于 JavaScript 的一些核心功能。

**JavaScript 举例说明:**

例如，在 Torque 中可能会声明一个内置函数来实现 `Array.prototype.push` 方法。在 `declaration-visitor.cc` 中，会处理类似以下 Torque 声明：

```torque
builtin ArrayPush<T>(implicit context: NativeContext, receiver: JSReceiver, ...arguments): Number
    labels FoundHole {
  // ... 实现 Array.prototype.push 的逻辑 ...
  return arguments.length;
}
```

这个 Torque 声明会被 `declaration-visitor.cc` 解析，并注册为一个名为 `ArrayPush` 的内置函数，它接收一个接收者 (receiver)，以及可变数量的参数 (arguments)，并返回一个数字 (表示数组的新长度)。

**对应的 JavaScript 代码:**

```javascript
const arr = [1, 2, 3];
const newLength = arr.push(4, 5); // 调用了 Array.prototype.push，对应 Torque 中的 ArrayPush
console.log(arr); // 输出: [1, 2, 3, 4, 5]
console.log(newLength); // 输出: 5
```

**代码逻辑推理 (假设输入与输出):**

假设 `declaration-visitor.cc` 正在处理以下 Torque 代码片段：

```torque
namespace MyNamespace {
  const MyConstant: Number = 10;
}

macro MyMacro(a: Number, b: Number): Number {
  return a + b;
}
```

**假设输入:**  一个表示上述 Torque 代码片段的 AST 节点。

**输出:**

1. **创建并注册命名空间 `MyNamespace`:**  `GetOrCreateNamespace("MyNamespace")` 会被调用，如果不存在则创建一个新的命名空间对象并注册。
2. **创建并注册常量 `MyConstant`:**  `Visit(ConstDeclaration*)` 方法会被调用，它会创建一个表示常量 `MyConstant` 的对象，类型为 `Number`，值为 10，并将其注册到 `MyNamespace` 命名空间下。
3. **创建并注册宏 `MyMacro`:**  `Visit(TorqueMacroDeclaration*)` 方法会被调用，它会创建一个表示宏 `MyMacro` 的对象，包含其参数类型 (`Number`, `Number`) 和返回类型 (`Number`)，以及宏的实现体，并将其注册到全局作用域或当前命名空间。

**涉及用户常见的编程错误:**

`declaration-visitor.cc` 中包含了对 Torque 代码的各种静态检查，它可以捕获一些用户常见的编程错误。例如：

1. **JavaScript 链接的内置函数返回值类型错误:**  如果用户声明了一个要链接到 JavaScript 的内置函数，但其返回值类型不是 `JSAny`，则会报错。

    **Torque 错误示例:**

    ```torque
    // 错误：JavaScript 链接的内置函数应该返回 JSAny
    builtin JavaScriptLinkedBuiltin(): Number {
      return 5;
    }
    ```

    **错误信息 (近似):** "Return type of JavaScript-linkage builtins has to be JSAny."

2. **JavaScript 链接的内置函数参数类型错误:**  类似地，如果 JavaScript 链接的内置函数的参数类型不是 `JSAny` (除非是 `extern javascript` 声明)，也会报错。

    **Torque 错误示例:**

    ```torque
    // 错误：JavaScript 链接的内置函数参数应该是 JSAny
    builtin JavaScriptLinkedBuiltinWithNumberArgument(arg: Number): JSAny {
      return arg;
    }
    ```

    **错误信息 (近似):** "Parameters of JavaScript-linkage builtins have to be a supertype of JSAny."

3. **在内置函数中使用结构体作为参数或返回值 (部分情况):**  除非有自定义的接口描述符，否则内置函数通常不支持结构体作为参数。

    **Torque 错误示例:**

    ```torque
    struct MyStruct {
      field1: Number;
    }

    // 错误：内置函数不支持结构体作为参数 (通常)
    builtin BuiltinWithStructArgument(arg: MyStruct): Number {
      return arg.field1;
    }
    ```

    **错误信息 (近似):** "Builtin do not support structs as arguments..."

4. **运行时函数缺少上下文参数:**  V8 的运行时函数通常需要一个上下文参数。

    **Torque 错误示例:**

    ```torque
    // 错误：运行时函数需要上下文参数
    runtime RuntimeFunction(): Smi;
    ```

    **错误信息 (近似):** "Missing parameters for runtime function, at least the context parameter is required."

5. **运行时函数参数或返回值类型错误:** 运行时函数的参数和返回值通常需要是强类型标签值。

    **Torque 错误示例:**

    ```torque
    // 错误：运行时函数返回值需要是强类型标签值
    runtime RuntimeFunction(context: Context): Number;

    // 错误：运行时函数参数需要是强类型标签值
    runtime AnotherRuntimeFunction(context: Context, arg: Number): Smi;
    ```

    **错误信息 (近似):** "runtime functions can only return strong tagged values..." 或 "runtime functions can only take strong tagged parameters..."

总而言之，`v8/src/torque/declaration-visitor.cc` 是 Torque 编译器的核心组件，负责解析和验证 Torque 源代码中的声明，并将这些声明注册到系统中，为后续的类型检查、代码生成等阶段提供必要的信息，同时也帮助开发者尽早发现代码中的错误。

### 提示词
```
这是目录为v8/src/torque/declaration-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/declaration-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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