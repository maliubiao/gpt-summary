Response: The user wants a summary of the C++ code in `v8/src/torque/implementation-visitor.cc`. This is part 3 of 4, suggesting the user wants a cumulative understanding of the file's functionality. I should focus on the code provided in this snippet and how it builds upon the previous parts.

Based on the code, this part of `ImplementationVisitor.cc` deals with:

1. **Visiting and generating code for various expressions:**
    *   `CallExpression`: Handling function calls, including looking up callables, generating pointer calls for local values, and propagating bitfield marks.
    *   `CallMethodExpression`: Handling method calls on objects, including looking up methods and generating calls.
    *   `IntrinsicCallExpression`: Handling calls to intrinsic functions.
2. **Generating control flow constructs:**
    *   `GenerateBranch`: Generating conditional branches.
    *   `GenerateBoolConstant`: Creating boolean constants.
    *   `GenerateExpressionBranch`: Generating branches based on expression evaluation.
    *   `GenerateImplicitConvert`: Handling implicit type conversions.
    *   `GenerateLabelGoto`: Generating gotos to labels.
    *   `LabelsFromIdentifiers`:  Resolving identifiers to labels.
3. **Lowering parameters for code generation:**
    *   `LowerParameter`:  Handling parameter passing, potentially flattening struct parameters.
    *   `LowerLabelParameter`:  Handling label parameters, potentially flattening struct label parameters.
4. **Managing labels and names:**
    *   Defining external names for labels and parameters.
5. **Handling built-in functions:**
    *   `GenerateBuiltinDefinitionsAndInterfaceDescriptors`: Generating header files for built-in function definitions and interface descriptors.
6. **Generating class definitions and related code:**
    *   Generating visitor lists.
    *   Generating bitfield definitions.
    *   Generating C++ class definitions, including fields, accessors, constructors, and size calculations. This involves a `CppClassGenerator` class.
7. **Generating factory functions for classes.**

Regarding the relationship with JavaScript, this part focuses on the implementation details of how Torque (a language used for V8's internal code) is translated into C++. The generated C++ code will eventually be executed by V8 to perform JavaScript operations.

For example, when a JavaScript function is called, the Torque compiler might generate a `CallExpression` which will be handled by `ImplementationVisitor::Visit(CallExpression*)`. The generated C++ code will then perform the actual function call within the V8 engine. Similarly, when a JavaScript object's method is called, the `CallMethodExpression` and the associated code generation will be involved.

I need to provide a JavaScript example that demonstrates the kind of operations these C++ functions are dealing with.
这是 `v8/src/torque/implementation-visitor.cc` 文件的第三部分，主要负责将 Torque 语法树中的表达式和声明转换为底层的代码表示（例如，V8 的汇编指令或 C++ 代码）。它延续了之前部分的工作，进一步处理更复杂的语言结构，并开始生成与 V8 运行时相关的具体实现。

**主要功能归纳:**

1. **处理函数调用表达式 (`CallExpression`):**
    *   查找被调用函数（包括本地函数和全局函数）。
    *   处理模板参数和普通参数。
    *   生成函数调用的代码，可能是直接的指针调用（对于本地值）或通过更通用的调用机制。
    *   支持尾调用优化。
    *   在收集语言服务器数据和 Kythe 数据时，记录函数调用的信息。
    *   处理一些特殊的操作符调用，例如 `!` 和 `==`，并传播 bitfield 的标记信息。

2. **处理方法调用表达式 (`CallMethodExpression`):**
    *   获取方法调用的目标对象。
    *   查找目标对象类型中的方法。
    *   生成方法调用的代码。

3. **处理内置函数调用表达式 (`IntrinsicCallExpression`):**
    *   生成对内置函数的调用。

4. **生成控制流语句:**
    *   `GenerateBranch`: 生成条件分支指令。
    *   `GenerateBoolConstant`: 生成布尔常量。
    *   `GenerateExpressionBranch`: 基于表达式的值生成分支。
    *   `GenerateImplicitConvert`: 处理类型之间的隐式转换。
    *   `GenerateLabelGoto`: 生成跳转到标签的代码。
    *   `LabelsFromIdentifiers`: 将标识符转换为标签。

5. **处理参数和标签:**
    *   `LowerParameter`: 将参数降级为更底层的表示形式，例如处理结构体参数的展开。
    *   `LowerLabelParameter`: 处理标签参数。
    *   定义外部标签和参数的名称。

6. **处理内置函数的定义和接口描述符:**
    *   `GenerateBuiltinDefinitionsAndInterfaceDescriptors`: 生成包含内置函数定义和接口描述符的头文件，这些描述符用于描述内置函数的参数和返回值类型，以及调用约定。

7. **生成类定义和相关代码:**
    *   `GenerateVisitorLists`: 生成用于对象访问的 visitor 列表。
    *   `GenerateBitFields`: 生成 bitfield 的定义。
    *   `GenerateClassDefinitions`: 生成 C++ 类的定义，包括字段、访问器、构造函数等。这个过程中使用了 `CppClassGenerator` 类来辅助生成代码。

8. **生成类的工厂函数:**
    *   为需要在 JavaScript 中创建的对象生成工厂函数。

**与 JavaScript 功能的关系及示例:**

这部分代码与 JavaScript 功能的关系非常紧密，因为它负责将 Torque 代码（V8 内部用于定义运行时行为的一种语言）转换为 V8 能够执行的 C++ 代码。

**JavaScript 示例:**

```javascript
// 假设 V8 内部定义了一个名为 "StringLength" 的 Torque 内置函数，用于获取字符串长度。

function getStringLength(str) {
  return str.length; // JavaScript 代码
}

// 当 V8 编译上述 JavaScript 代码时，对于 `str.length` 的访问，
// Torque 可能会生成一个类似以下的 IntrinsicCallExpression:

// IntrinsicCallExpression {
//   name: Identifier { value: "StringLength" },
//   arguments: [
//     Identifier { value: "str" }
//   ]
// }

// `ImplementationVisitor::Visit(IntrinsicCallExpression* expr)` 函数会处理这个表达式，
// 并生成相应的 C++ 代码来调用 V8 内部实现的 StringLength 函数。

// 又例如，考虑一个简单的 JavaScript 函数调用：

function add(a, b) {
  return a + b;
}

let result = add(5, 10); // JavaScript 代码

// 当 V8 编译 `add(5, 10)` 时，可能会生成一个类似以下的 CallExpression:

// CallExpression {
//   callee: Identifier { value: "add" },
//   arguments: [
//     Literal { value: 5 },
//     Literal { value: 10 }
//   ]
// }

// `ImplementationVisitor::Visit(CallExpression* expr)` 函数会处理这个表达式，
// 查找 `add` 函数的 Torque 定义，并生成 C++ 代码来执行 `add` 函数的逻辑。

// 再例如，一个 JavaScript 对象的方法调用：

const obj = {
  value: 42,
  getValue() {
    return this.value;
  }
};

let theValue = obj.getValue(); // JavaScript 代码

// 当 V8 编译 `obj.getValue()` 时，可能会生成一个类似以下的 CallMethodExpression:

// CallMethodExpression {
//   target: Identifier { value: "obj" },
//   method: Identifier { value: "getValue" },
//   arguments: []
// }

// `ImplementationVisitor::Visit(CallMethodExpression* expr)` 函数会处理这个表达式，
// 找到 `obj` 的类型以及 `getValue` 方法，并生成 C++ 代码来调用该方法。
```

**总结:**

这部分 `ImplementationVisitor.cc` 的核心职责是将高级的 Torque 代码转换为 V8 能够理解和执行的低级代码。它处理了函数调用、方法调用、内置函数调用等关键的语言结构，并开始生成与 V8 内部对象模型和运行时机制紧密相关的 C++ 代码，例如内置函数的接口描述符和类的定义。这些生成的 C++ 代码最终支撑着 JavaScript 代码的执行。

### 提示词
```
这是目录为v8/src/torque/implementation-visitor.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```
) return scope.Yield(ref.heap_slice());
    }
    ReportError("Unable to create a heap reference.");
  }

  Arguments arguments;
  QualifiedName name = QualifiedName(expr->callee->namespace_qualification,
                                     expr->callee->name->value);
  TypeVector specialization_types =
      TypeVisitor::ComputeTypeVector(expr->callee->generic_arguments);
  bool has_template_arguments = !specialization_types.empty();
  for (Expression* arg : expr->arguments)
    arguments.parameters.push_back(Visit(arg));
  arguments.labels = LabelsFromIdentifiers(expr->labels);
  if (!has_template_arguments && name.namespace_qualification.empty() &&
      TryLookupLocalValue(name.name)) {
    return scope.Yield(
        GeneratePointerCall(expr->callee, arguments, is_tailcall));
  } else {
    if (GlobalContext::collect_language_server_data()) {
      Callable* callable = LookupCallable(name, Declarations::Lookup(name),
                                          arguments, specialization_types);
      LanguageServerData::AddDefinition(expr->callee->name->pos,
                                        callable->IdentifierPosition());
    }
    if (GlobalContext::collect_kythe_data()) {
      Callable* callable = LookupCallable(name, Declarations::Lookup(name),
                                          arguments, specialization_types);
      Callable* caller = CurrentCallable::Get();
      KytheData::AddCall(caller, expr->callee->name->pos, callable);
    }
    if (expr->callee->name->value == "!" && arguments.parameters.size() == 1) {
      PropagateBitfieldMark(expr->arguments[0], expr);
    }
    if (expr->callee->name->value == "==" && arguments.parameters.size() == 2) {
      if (arguments.parameters[0].type()->IsConstexpr()) {
        PropagateBitfieldMark(expr->arguments[1], expr);
      } else if (arguments.parameters[1].type()->IsConstexpr()) {
        PropagateBitfieldMark(expr->arguments[0], expr);
      }
    }
    return scope.Yield(
        GenerateCall(name, arguments, specialization_types, is_tailcall));
  }
}

VisitResult ImplementationVisitor::Visit(CallMethodExpression* expr) {
  StackScope scope(this);
  Arguments arguments;
  std::string method_name = expr->method->name->value;
  TypeVector specialization_types =
      TypeVisitor::ComputeTypeVector(expr->method->generic_arguments);
  LocationReference target = GetLocationReference(expr->target);
  if (!target.IsVariableAccess()) {
    VisitResult result = GenerateFetchFromLocation(target);
    target = LocationReference::Temporary(result, "this parameter");
  }
  const AggregateType* target_type =
      (*target.ReferencedType())->AggregateSupertype().value_or(nullptr);
  if (!target_type) {
    ReportError("target of method call not a struct or class type");
  }
  for (Expression* arg : expr->arguments) {
    arguments.parameters.push_back(Visit(arg));
  }
  arguments.labels = LabelsFromIdentifiers(expr->labels);
  TypeVector argument_types = arguments.parameters.ComputeTypeVector();
  DCHECK_EQ(expr->method->namespace_qualification.size(), 0);
  QualifiedName qualified_name = QualifiedName(method_name);
  Callable* callable = LookupMethod(method_name, target_type, arguments, {});
  if (GlobalContext::collect_language_server_data()) {
    LanguageServerData::AddDefinition(expr->method->name->pos,
                                      callable->IdentifierPosition());
  }
  if (GlobalContext::collect_kythe_data()) {
    Callable* caller = CurrentCallable::Get();
    KytheData::AddCall(caller, expr->method->name->pos, callable);
  }
  return scope.Yield(GenerateCall(callable, target, arguments, {}, false));
}

VisitResult ImplementationVisitor::Visit(IntrinsicCallExpression* expr) {
  StackScope scope(this);
  Arguments arguments;
  TypeVector specialization_types =
      TypeVisitor::ComputeTypeVector(expr->generic_arguments);
  for (Expression* arg : expr->arguments)
    arguments.parameters.push_back(Visit(arg));
  return scope.Yield(
      GenerateCall(expr->name->value, arguments, specialization_types, false));
}

void ImplementationVisitor::GenerateBranch(const VisitResult& condition,
                                           Block* true_block,
                                           Block* false_block) {
  DCHECK_EQ(condition,
            VisitResult(TypeOracle::GetBoolType(), assembler().TopRange(1)));
  assembler().Branch(true_block, false_block);
}

VisitResult ImplementationVisitor::GenerateBoolConstant(bool constant) {
  return GenerateImplicitConvert(TypeOracle::GetBoolType(),
                                 VisitResult(TypeOracle::GetConstexprBoolType(),
                                             constant ? "true" : "false"));
}

void ImplementationVisitor::GenerateExpressionBranch(Expression* expression,
                                                     Block* true_block,
                                                     Block* false_block) {
  StackScope stack_scope(this);
  VisitResult expression_result = this->Visit(expression);
  expression_result = stack_scope.Yield(
      GenerateImplicitConvert(TypeOracle::GetBoolType(), expression_result));
  GenerateBranch(expression_result, true_block, false_block);
}

VisitResult ImplementationVisitor::GenerateImplicitConvert(
    const Type* destination_type, VisitResult source) {
  StackScope scope(this);
  if (source.type() == TypeOracle::GetNeverType()) {
    ReportError("it is not allowed to use a value of type never");
  }

  if (destination_type == source.type()) {
    return scope.Yield(GenerateCopy(source));
  }

  if (auto from = TypeOracle::ImplicitlyConvertableFrom(destination_type,
                                                        source.type())) {
    return scope.Yield(GenerateCall(kFromConstexprMacroName,
                                    Arguments{{source}, {}},
                                    {destination_type, *from}, false));
  } else if (IsAssignableFrom(destination_type, source.type())) {
    source.SetType(destination_type);
    return scope.Yield(GenerateCopy(source));
  } else {
    std::stringstream s;
    if (const TopType* top_type = TopType::DynamicCast(source.type())) {
      s << "undefined expression of type " << *destination_type << ": the "
        << top_type->reason();
    } else {
      s << "cannot use expression of type " << *source.type()
        << " as a value of type " << *destination_type;
    }
    ReportError(s.str());
  }
}

StackRange ImplementationVisitor::GenerateLabelGoto(
    LocalLabel* label, std::optional<StackRange> arguments) {
  return assembler().Goto(label->block, arguments ? arguments->Size() : 0);
}

std::vector<Binding<LocalLabel>*> ImplementationVisitor::LabelsFromIdentifiers(
    const std::vector<Identifier*>& names) {
  std::vector<Binding<LocalLabel>*> result;
  result.reserve(names.size());
  for (const auto& name : names) {
    Binding<LocalLabel>* label = LookupLabel(name->value);
    result.push_back(label);

    // Link up labels in "otherwise" part of the call expression with
    // either the label in the signature of the calling macro or the label
    // block ofa surrounding "try".
    if (GlobalContext::collect_language_server_data()) {
      LanguageServerData::AddDefinition(name->pos,
                                        label->declaration_position());
    }
    // TODO(v8:12261): Might have to track KytheData here.
  }
  return result;
}

StackRange ImplementationVisitor::LowerParameter(
    const Type* type, const std::string& parameter_name,
    Stack<std::string>* lowered_parameters) {
  if (std::optional<const StructType*> struct_type = type->StructSupertype()) {
    StackRange range = lowered_parameters->TopRange(0);
    for (auto& field : (*struct_type)->fields()) {
      StackRange parameter_range = LowerParameter(
          field.name_and_type.type,
          parameter_name + "." + field.name_and_type.name, lowered_parameters);
      range.Extend(parameter_range);
    }
    return range;
  } else {
    lowered_parameters->Push(parameter_name);
    return lowered_parameters->TopRange(1);
  }
}

void ImplementationVisitor::LowerLabelParameter(
    const Type* type, const std::string& parameter_name,
    std::vector<std::string>* lowered_parameters) {
  if (std::optional<const StructType*> struct_type = type->StructSupertype()) {
    for (auto& field : (*struct_type)->fields()) {
      LowerLabelParameter(
          field.name_and_type.type,
          "&((*" + parameter_name + ")." + field.name_and_type.name + ")",
          lowered_parameters);
    }
  } else {
    lowered_parameters->push_back(parameter_name);
  }
}

std::string ImplementationVisitor::ExternalLabelName(
    const std::string& label_name) {
  return "label_" + label_name;
}

std::string ImplementationVisitor::ExternalLabelParameterName(
    const std::string& label_name, size_t i) {
  return "label_" + label_name + "_parameter_" + std::to_string(i);
}

std::string ImplementationVisitor::ExternalParameterName(
    const std::string& name) {
  return std::string("p_") + name;
}

bool IsCompatibleSignature(const Signature& sig, const TypeVector& types,
                           size_t label_count) {
  auto i = sig.parameter_types.types.begin() + sig.implicit_count;
  if ((sig.parameter_types.types.size() - sig.implicit_count) > types.size())
    return false;
  if (sig.labels.size() != label_count) return false;
  for (auto current : types) {
    if (i == sig.parameter_types.types.end()) {
      if (!sig.parameter_types.var_args) return false;
      if (!IsAssignableFrom(TypeOracle::GetObjectType(), current)) return false;
    } else {
      if (!IsAssignableFrom(*i++, current)) return false;
    }
  }
  return true;
}

std::optional<Block*> ImplementationVisitor::GetCatchBlock() {
  std::optional<Block*> catch_block;
  if (TryLookupLabel(kCatchLabelName)) {
    catch_block = assembler().NewBlock(std::nullopt, true);
  }
  return catch_block;
}

void ImplementationVisitor::GenerateCatchBlock(
    std::optional<Block*> catch_block) {
  if (catch_block) {
    std::optional<Binding<LocalLabel>*> catch_handler =
        TryLookupLabel(kCatchLabelName);
    // Reset the local scopes to prevent the macro calls below from using the
    // current catch handler.
    BindingsManagersScope bindings_managers_scope;
    if (assembler().CurrentBlockIsComplete()) {
      assembler().Bind(*catch_block);
      GenerateCall(QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                                 "GetAndResetPendingMessage"),
                   Arguments{{}, {}}, {}, false);
      assembler().Goto((*catch_handler)->block, 2);
    } else {
      CfgAssemblerScopedTemporaryBlock temp(&assembler(), *catch_block);
      GenerateCall(QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                                 "GetAndResetPendingMessage"),
                   Arguments{{}, {}}, {}, false);
      assembler().Goto((*catch_handler)->block, 2);
    }
  }
}
void ImplementationVisitor::VisitAllDeclarables() {
  CurrentCallable::Scope current_callable(nullptr);
  const std::vector<std::unique_ptr<Declarable>>& all_declarables =
      GlobalContext::AllDeclarables();

  // This has to be an index-based loop because all_declarables can be extended
  // during the loop.
  for (size_t i = 0; i < all_declarables.size(); ++i) {
    try {
      Visit(all_declarables[i].get());
    } catch (TorqueAbortCompilation&) {
      // Recover from compile errors here. The error is recorded already.
    }
  }

  // Do the same for macros which generate C++ code.
  output_type_ = OutputType::kCC;
  const std::vector<std::pair<TorqueMacro*, SourceId>>& cc_macros =
      GlobalContext::AllMacrosForCCOutput();
  for (size_t i = 0; i < cc_macros.size(); ++i) {
    try {
      Visit(static_cast<Declarable*>(cc_macros[i].first), cc_macros[i].second);
    } catch (TorqueAbortCompilation&) {
      // Recover from compile errors here. The error is recorded already.
    }
  }

  // Do the same for macros which generate C++ debug code.
  // The set of macros is the same as C++ macros.
  output_type_ = OutputType::kCCDebug;
  const std::vector<std::pair<TorqueMacro*, SourceId>>& cc_debug_macros =
      GlobalContext::AllMacrosForCCDebugOutput();
  for (size_t i = 0; i < cc_debug_macros.size(); ++i) {
    try {
      Visit(static_cast<Declarable*>(cc_debug_macros[i].first),
            cc_debug_macros[i].second);
    } catch (TorqueAbortCompilation&) {
      // Recover from compile errors here. The error is recorded already.
    }
  }

  output_type_ = OutputType::kCSA;
}

void ImplementationVisitor::Visit(Declarable* declarable,
                                  std::optional<SourceId> file) {
  CurrentScope::Scope current_scope(declarable->ParentScope());
  CurrentSourcePosition::Scope current_source_position(declarable->Position());
  CurrentFileStreams::Scope current_file_streams(
      &GlobalContext::GeneratedPerFile(file ? *file
                                            : declarable->Position().source));
  if (Callable* callable = Callable::DynamicCast(declarable)) {
    if (!callable->ShouldGenerateExternalCode(output_type_))
      CurrentFileStreams::Get() = nullptr;
  }
  switch (declarable->kind()) {
    case Declarable::kExternMacro:
      return Visit(ExternMacro::cast(declarable));
    case Declarable::kTorqueMacro:
      return Visit(TorqueMacro::cast(declarable));
    case Declarable::kMethod:
      return Visit(Method::cast(declarable));
    case Declarable::kBuiltin:
      return Visit(Builtin::cast(declarable));
    case Declarable::kTypeAlias:
      return Visit(TypeAlias::cast(declarable));
    case Declarable::kNamespaceConstant:
      return Visit(NamespaceConstant::cast(declarable));
    case Declarable::kRuntimeFunction:
    case Declarable::kIntrinsic:
    case Declarable::kExternConstant:
    case Declarable::kNamespace:
    case Declarable::kGenericCallable:
    case Declarable::kGenericType:
      return;
  }
}

std::string MachineTypeString(const Type* type) {
  if (type->IsSubtypeOf(TypeOracle::GetSmiType())) {
    return "MachineType::TaggedSigned()";
  }
  if (type->IsSubtypeOf(TypeOracle::GetHeapObjectType())) {
    return "MachineType::TaggedPointer()";
  }
  if (type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
    return "MachineType::AnyTagged()";
  }
  return "MachineTypeOf<" + type->GetGeneratedTNodeTypeName() + ">::value";
}

void ImplementationVisitor::GenerateBuiltinDefinitionsAndInterfaceDescriptors(
    const std::string& output_directory) {
  std::stringstream builtin_definitions;
  std::string builtin_definitions_file_name = "builtin-definitions.h";

  // This file contains plain interface descriptor definitions and has to be
  // included in the middle of interface-descriptors.h. Thus it is not a normal
  // header file and uses the .inc suffix instead of the .h suffix.
  std::stringstream interface_descriptors;
  std::string interface_descriptors_file_name = "interface-descriptors.inc";
  {
    IncludeGuardScope builtin_definitions_include_guard(
        builtin_definitions, builtin_definitions_file_name);

    builtin_definitions
        << "\n"
           "#define BUILTIN_LIST_FROM_TORQUE(CPP, TFJ, TFC, TFS, TFH, "
           "ASM) "
           "\\\n";
    for (auto& declarable : GlobalContext::AllDeclarables()) {
      Builtin* builtin = Builtin::DynamicCast(declarable.get());
      if (!builtin || builtin->IsExternal()) continue;
      if (builtin->IsStub()) {
        builtin_definitions << "TFC(" << builtin->ExternalName() << ", "
                            << builtin->ExternalName();
        if (!builtin->HasCustomInterfaceDescriptor()) {
          std::string descriptor_name = builtin->ExternalName() + "Descriptor";
          bool has_context_parameter =
              builtin->signature().HasContextParameter();
          size_t kFirstNonContextParameter = has_context_parameter ? 1 : 0;
          TypeVector return_types = LowerType(builtin->signature().return_type);

          interface_descriptors << "class " << descriptor_name
                                << " : public StaticCallInterfaceDescriptor<"
                                << descriptor_name << "> {\n";

          interface_descriptors << " public:\n";

          // Currently, no torque-defined builtins are directly exposed to
          // objects inside the sandbox via the code pointer table.
          interface_descriptors << "  INTERNAL_DESCRIPTOR()\n";

          if (has_context_parameter) {
            interface_descriptors << "  DEFINE_RESULT_AND_PARAMETERS(";
          } else {
            interface_descriptors
                << "  DEFINE_RESULT_AND_PARAMETERS_NO_CONTEXT(";
          }
          interface_descriptors << return_types.size();
          for (size_t i = kFirstNonContextParameter;
               i < builtin->parameter_names().size(); ++i) {
            Identifier* parameter = builtin->parameter_names()[i];
            interface_descriptors << ", k" << CamelifyString(parameter->value);
          }
          interface_descriptors << ")\n";

          interface_descriptors << "  DEFINE_RESULT_AND_PARAMETER_TYPES(";
          PrintCommaSeparatedList(interface_descriptors, return_types,
                                  MachineTypeString);
          bool is_first = return_types.empty();
          for (size_t i = kFirstNonContextParameter;
               i < builtin->parameter_names().size(); ++i) {
            const Type* type = builtin->signature().parameter_types.types[i];
            interface_descriptors << (is_first ? "" : ", ")
                                  << MachineTypeString(type);
            is_first = false;
          }
          interface_descriptors << ")\n";

          interface_descriptors << "  DECLARE_DEFAULT_DESCRIPTOR("
                                << descriptor_name << ")\n";
          interface_descriptors << "};\n\n";
        }
      } else {
        builtin_definitions << "TFJ(" << builtin->ExternalName();
        if (builtin->IsVarArgsJavaScript()) {
          builtin_definitions << ", kDontAdaptArgumentsSentinel";
        } else {
          DCHECK(builtin->IsFixedArgsJavaScript());
          // FixedArg javascript builtins need to offer the parameter
          // count.
          int parameter_count =
              static_cast<int>(builtin->signature().ExplicitCount());
          builtin_definitions << ", JSParameterCount(" << parameter_count
                              << ")";
          // And the receiver is explicitly declared.
          builtin_definitions << ", kReceiver";
          for (size_t i = builtin->signature().implicit_count;
               i < builtin->parameter_names().size(); ++i) {
            Identifier* parameter = builtin->parameter_names()[i];
            builtin_definitions << ", k" << CamelifyString(parameter->value);
          }
        }
      }
      builtin_definitions << ") \\\n";
    }
    builtin_definitions << "\n";

    builtin_definitions
        << "#define TORQUE_FUNCTION_POINTER_TYPE_TO_BUILTIN_MAP(V) \\\n";
    for (const BuiltinPointerType* type :
         TypeOracle::AllBuiltinPointerTypes()) {
      Builtin* example_builtin =
          Declarations::FindSomeInternalBuiltinWithType(type);
      if (!example_builtin) {
        CurrentSourcePosition::Scope current_source_position(
            SourcePosition{CurrentSourceFile::Get(), LineAndColumn::Invalid(),
                           LineAndColumn::Invalid()});
        ReportError("unable to find any builtin with type \"", *type, "\"");
      }
      builtin_definitions << "  V(" << type->function_pointer_type_id() << ","
                          << example_builtin->ExternalName() << ")\\\n";
    }
    builtin_definitions << "\n";
  }
  WriteFile(output_directory + "/" + builtin_definitions_file_name,
            builtin_definitions.str());
  WriteFile(output_directory + "/" + interface_descriptors_file_name,
            interface_descriptors.str());
}

namespace {

enum class FieldSectionType : uint32_t {
  kNoSection = 0,
  kWeakSection = 1 << 0,
  kStrongSection = 2 << 0,
  kScalarSection = 3 << 0
};

bool IsPointerSection(FieldSectionType type) {
  return type == FieldSectionType::kWeakSection ||
         type == FieldSectionType::kStrongSection;
}

using FieldSections = base::Flags<FieldSectionType>;

std::string ToString(FieldSectionType type) {
  switch (type) {
    case FieldSectionType::kNoSection:
      return "NoSection";
    case FieldSectionType::kWeakSection:
      return "WeakFields";
    case FieldSectionType::kStrongSection:
      return "StrongFields";
    case FieldSectionType::kScalarSection:
      return "ScalarFields";
  }
  UNREACHABLE();
}

class FieldOffsetsGenerator {
 public:
  explicit FieldOffsetsGenerator(const ClassType* type) : type_(type) {}

  virtual void WriteField(const Field& f, const std::string& size_string) = 0;
  virtual void WriteFieldOffsetGetter(const Field& f) = 0;
  virtual void WriteMarker(const std::string& marker) = 0;

  virtual ~FieldOffsetsGenerator() { CHECK(is_finished_); }

  void RecordOffsetFor(const Field& f) {
    CHECK(!is_finished_);
    UpdateSection(f);

    // Emit kHeaderSize before any indexed field.
    if (f.index.has_value() && !header_size_emitted_) {
      WriteMarker("kHeaderSize");
      header_size_emitted_ = true;
    }

    // We don't know statically how much space an indexed field takes, so report
    // it as zero.
    std::string size_string = "0";
    if (!f.index.has_value()) {
      size_t field_size;
      std::tie(field_size, size_string) = f.GetFieldSizeInformation();
    }
    if (f.offset.has_value()) {
      WriteField(f, size_string);
    } else {
      WriteFieldOffsetGetter(f);
    }
  }

  void Finish() {
    End(current_section_);
    if (!(completed_sections_ & FieldSectionType::kWeakSection)) {
      Begin(FieldSectionType::kWeakSection);
      End(FieldSectionType::kWeakSection);
    }
    if (!(completed_sections_ & FieldSectionType::kStrongSection)) {
      Begin(FieldSectionType::kStrongSection);
      End(FieldSectionType::kStrongSection);
    }
    is_finished_ = true;

    // In the presence of indexed fields, we already emitted kHeaderSize before
    // the indexed field.
    if (!type_->IsShape() && !header_size_emitted_) {
      WriteMarker("kHeaderSize");
    }
    if (!type_->IsAbstract() && type_->HasStaticSize()) {
      WriteMarker("kSize");
    }
  }

 protected:
  const ClassType* type_;

 private:
  FieldSectionType GetSectionFor(const Field& f) {
    const Type* field_type = f.name_and_type.type;
    if (field_type == TypeOracle::GetVoidType()) {
      // Allow void type for marker constants of size zero.
      return current_section_;
    }
    StructType::Classification struct_contents =
        StructType::ClassificationFlag::kEmpty;
    if (auto field_as_struct = field_type->StructSupertype()) {
      struct_contents = (*field_as_struct)->ClassifyContents();
    }
    if ((struct_contents & StructType::ClassificationFlag::kStrongTagged) &&
        (struct_contents & StructType::ClassificationFlag::kWeakTagged)) {
      // It's okay for a struct to contain both strong and weak data. We'll just
      // treat the whole thing as weak. This is required for DescriptorEntry.
      struct_contents &= ~StructType::Classification(
          StructType::ClassificationFlag::kStrongTagged);
    }
    bool struct_contains_tagged_fields =
        (struct_contents & StructType::ClassificationFlag::kStrongTagged) ||
        (struct_contents & StructType::ClassificationFlag::kWeakTagged);
    if (struct_contains_tagged_fields &&
        (struct_contents & StructType::ClassificationFlag::kUntagged)) {
      // We can't declare what section a struct goes in if it has multiple
      // categories of data within.
      Error(
          "Classes do not support fields which are structs containing both "
          "tagged and untagged data.")
          .Position(f.pos);
    }
    if ((field_type->IsSubtypeOf(TypeOracle::GetStrongTaggedType()) ||
         struct_contents == StructType::ClassificationFlag::kStrongTagged) &&
        !f.custom_weak_marking) {
      return FieldSectionType::kStrongSection;
    } else if (field_type->IsSubtypeOf(TypeOracle::GetTaggedType()) ||
               struct_contains_tagged_fields) {
      return FieldSectionType::kWeakSection;
    } else {
      return FieldSectionType::kScalarSection;
    }
  }
  void UpdateSection(const Field& f) {
    FieldSectionType type = GetSectionFor(f);
    if (current_section_ == type) return;
    if (IsPointerSection(type)) {
      if (completed_sections_ & type) {
        std::stringstream s;
        s << "cannot declare field " << f.name_and_type.name << " in class "
          << type_->name() << ", because section " << ToString(type)
          << " to which it belongs has already been finished.";
        Error(s.str()).Position(f.pos);
      }
    }
    End(current_section_);
    current_section_ = type;
    Begin(current_section_);
  }
  void Begin(FieldSectionType type) {
    DCHECK(type != FieldSectionType::kNoSection);
    if (!IsPointerSection(type)) return;
    WriteMarker("kStartOf" + ToString(type) + "Offset");
  }
  void End(FieldSectionType type) {
    if (!IsPointerSection(type)) return;
    completed_sections_ |= type;
    WriteMarker("kEndOf" + ToString(type) + "Offset");
  }

  FieldSectionType current_section_ = FieldSectionType::kNoSection;
  FieldSections completed_sections_ = FieldSectionType::kNoSection;
  bool is_finished_ = false;
  bool header_size_emitted_ = false;
};

void GenerateClassExport(const ClassType* type, std::ostream& header,
                         std::ostream& inl_header) {
  const ClassType* super = type->GetSuperClass();
  std::string parent = "TorqueGenerated" + type->name() + "<" + type->name() +
                       ", " + super->name() + ">";
  header << "class " << type->name() << " : public " << parent << " {\n";
  header << " public:\n";
  if (type->ShouldGenerateBodyDescriptor()) {
    header << "  class BodyDescriptor;\n";
  }
  header << "  TQ_OBJECT_CONSTRUCTORS(" << type->name() << ")\n";
  header << "};\n\n";
  inl_header << "TQ_OBJECT_CONSTRUCTORS_IMPL(" << type->name() << ")\n";
}

}  // namespace

void ImplementationVisitor::GenerateVisitorLists(
    const std::string& output_directory) {
  std::stringstream header;
  std::string file_name = "visitor-lists.h";
  {
    IncludeGuardScope include_guard(header, file_name);

    header << "#define TORQUE_INSTANCE_TYPE_TO_BODY_DESCRIPTOR_LIST(V)\\\n";
    for (const ClassType* type : TypeOracle::GetClasses()) {
      if (type->ShouldGenerateBodyDescriptor() && type->OwnInstanceType()) {
        std::string type_name =
            CapifyStringWithUnderscores(type->name()) + "_TYPE";
        header << "V(" << type_name << "," << type->name() << ")\\\n";
      }
    }
    header << "\n";

    header << "#define TORQUE_DATA_ONLY_VISITOR_ID_LIST(V)\\\n";
    for (const ClassType* type : TypeOracle::GetClasses()) {
      if (type->ShouldGenerateBodyDescriptor() &&
          type->HasNoPointerSlotsExceptMap()) {
        header << "V(" << type->name() << ")\\\n";
      }
    }
    header << "\n";

    header << "#define TORQUE_POINTER_VISITOR_ID_LIST(V)\\\n";
    for (const ClassType* type : TypeOracle::GetClasses()) {
      if (type->ShouldGenerateBodyDescriptor() &&
          !type->HasNoPointerSlotsExceptMap()) {
        header << "V(" << type->name() << ")\\\n";
      }
    }
    header << "\n";
  }
  const std::string output_header_path = output_directory + "/" + file_name;
  WriteFile(output_header_path, header.str());
}

void ImplementationVisitor::GenerateBitFields(
    const std::string& output_directory) {
  std::stringstream header;
  std::string file_name = "bit-fields.h";
  {
    IncludeGuardScope include_guard(header, file_name);
    header << "#include \"src/base/bit-field.h\"\n\n";
    NamespaceScope namespaces(header, {"v8", "internal"});

    for (const auto& type : TypeOracle::GetBitFieldStructTypes()) {
      bool all_single_bits = true;  // Track whether every field is one bit.
      header << "// " << type->GetPosition() << "\n";
      header << "#define DEFINE_TORQUE_GENERATED_"
             << CapifyStringWithUnderscores(type->name()) << "() \\\n";
      std::string type_name = type->GetConstexprGeneratedTypeName();
      for (const auto& field : type->fields()) {
        const char* suffix = field.num_bits == 1 ? "Bit" : "Bits";
        all_single_bits = all_single_bits && field.num_bits == 1;
        std::string field_type_name =
            field.name_and_type.type->GetConstexprGeneratedTypeName();
        header << "  using " << CamelifyString(field.name_and_type.name)
               << suffix << " = base::BitField<" << field_type_name << ", "
               << field.offset << ", " << field.num_bits << ", " << type_name
               << ">; \\\n";
      }

      // If every field is one bit, we can also generate a convenient enum.
      if (all_single_bits) {
        header << "  enum Flag: " << type_name << " { \\\n";
        header << "    kNone = 0, \\\n";
        for (const auto& field : type->fields()) {
          header << "    k" << CamelifyString(field.name_and_type.name) << " = "
                 << type_name << "{1} << " << field.offset << ", \\\n";
        }
        header << "  }; \\\n";
        header << "  using Flags = base::Flags<Flag>; \\\n";
        header << "  static constexpr int kFlagCount = "
               << type->fields().size() << "; \\\n";
      }

      header << "\n";
    }
  }
  const std::string output_header_path = output_directory + "/" + file_name;
  WriteFile(output_header_path, header.str());
}

namespace {

class ClassFieldOffsetGenerator : public FieldOffsetsGenerator {
 public:
  ClassFieldOffsetGenerator(std::ostream& header, std::ostream& inline_header,
                            const ClassType* type, std::string gen_name,
                            const ClassType* parent, bool use_templates = true)
      : FieldOffsetsGenerator(type),
        hdr_(header),
        inl_(inline_header),
        previous_field_end_(FirstFieldStart(type, parent, use_templates)),
        gen_name_(gen_name) {}

  void WriteField(const Field& f, const std::string& size_string) override {
    hdr_ << "  // " << f.pos << "\n";
    std::string field = "k" + CamelifyString(f.name_and_type.name) + "Offset";
    std::string field_end = field + "End";
    hdr_ << "  static constexpr int " << field << " = " << previous_field_end_
         << ";\n";
    hdr_ << "  static constexpr int " << field_end << " = " << field << " + "
         << size_string << " - 1;\n";
    previous_field_end_ = field_end + " + 1";
  }

  void WriteFieldOffsetGetter(const Field& f) override {
    // A static constexpr int is more convenient than a getter if the offset is
    // known.
    DCHECK(!f.offset.has_value());

    std::string function_name = CamelifyString(f.name_and_type.name) + "Offset";

    std::vector<cpp::TemplateParameter> params = {cpp::TemplateParameter("D"),
                                                  cpp::TemplateParameter("P")};
    cpp::Class owner(std::move(params), gen_name_);

    auto getter = cpp::Function::DefaultGetter("int", &owner, function_name);
    getter.PrintDeclaration(hdr_);
    getter.PrintDefinition(inl_, [&](std::ostream& stream) {
      // Item 1 in a flattened slice is the offset.
      stream << "  return static_cast<int>(std::get<1>("
             << Callable::PrefixNameForCCOutput(type_->GetSliceMacroName(f))
             << "(*static_cast<const D*>(this))));\n";
    });
  }
  void WriteMarker(const std::string& marker) override {
    hdr_ << "  static constexpr int " << marker << " = " << previous_field_end_
         << ";\n";
  }

 private:
  static std::string FirstFieldStart(const ClassType* type,
                                     const ClassType* parent,
                                     bool use_templates = true) {
    std::string parent_name = use_templates ? "P" : parent->name();

    if (type->IsLayoutDefinedInCpp()) {
      // TODO(leszeks): Hacked in support for some classes (e.g.
      // HeapObject) being mirrored by a *Layout class. Remove once
      // everything is ported to layout classes.
      if (parent_name == "HeapObject" || parent_name == "TrustedObject") {
        parent_name += "Layout";
      }

      return "sizeof(" + parent_name + ")";
    }

    if (parent && parent->IsShape()) {
      return parent_name + "::kSize";
    }
    return parent_name + "::kHeaderSize";
  }

  std::ostream& hdr_;
  std::ostream& inl_;
  std::string previous_field_end_;
  std::string gen_name_;
};

class CppClassGenerator {
 public:
  CppClassGenerator(const ClassType* type, std::ostream& header,
                    std::ostream& inl_header, std::ostream& impl)
      : type_(type),
        super_(type->GetSuperClass()),
        name_(type->name()),
        gen_name_("TorqueGenerated" + name_),
        gen_name_T_(gen_name_ + "<D, P>"),
        gen_name_I_(gen_name_ + "<" + name_ + ", " + super_->name() + ">"),
        hdr_(header),
        inl_(inl_header),
        impl_(impl) {}
  const std::string template_decl() const {
    return "template <class D, class P>";
  }

  void GenerateClass();
  void GenerateCppObjectDefinitionAsserts();
  void GenerateCppObjectLayoutDefinitionAsserts();

 private:
  SourcePosition Position();

  void GenerateClassConstructors();

  // Generates getter and setter runtime member functions for the given class
  // field. Traverses depth-first through any nested struct fields to generate
  // accessors for them also; struct_fields represents the stack of currently
  // active struct fields.
  void GenerateFieldAccessors(const Field& class_field,
                              std::vector<const Field*>& struct_fields);
  void EmitLoadFieldStatement(std::ostream& stream, const Field& class_field,
                              std::vector<const Field*>& struct_fields);
  void EmitStoreFieldStatement(std::ostream& stream, const Field& class_field,
                               std::vector<const Field*>& struct_fields);

  std::string GetFieldOffsetForAccessor(const Field& f);

  // Gets the C++ type name that should be used in accessors for referring to
  // the value of a class field.
  std::string GetTypeNameForAccessor(const Field& f);

  bool CanContainHeapObjects(const Type* t);

  const ClassType* type_;
  const ClassType* super_;
  const std::string name_;
  const std::string gen_name_;
  const std::string gen_name_T_;
  const std::string gen_name_I_;
  std::ostream& hdr_;
  std::ostream& inl_;
  std::ostream& impl_;
};

std::optional<std::vector<Field>> GetOrderedUniqueIndexFields(
    const ClassType& type) {
  std::vector<Field> result;
  std::set<std::string> index_names;
  for (const Field& field : type.ComputeAllFields()) {
    if (field.index) {
      auto name_and_type = ExtractSimpleFieldArraySize(type, field.index->expr);
      if (!name_and_type) {
        return std::nullopt;
      }
      index_names.insert(name_and_type->name);
    }
  }

  for (const Field& field : type.ComputeAllFields()) {
    if (index_names.count(field.name_and_type.name) != 0) {
      result.push_back(field);
    }
  }

  return result;
}

void CppClassGenerator::GenerateClass() {
  // Is<name>_NonInline(Tagged<HeapObject>)
  if (!type_->IsShape()) {
    cpp::Function f("Is"s + name_ + "_NonInline");
    f.SetDescription("Alias for Is"s + name_ + "() that avoids inlining.");
    f.SetExport(true);
    f.SetReturnType("bool");
    f.AddParameter("Tagged<HeapObject>", "o");

    f.PrintDeclaration(hdr_);
    hdr_ << "\n";
    f.PrintDefinition(impl_, [&](std::ostream& stream) {
      stream << "  return Is" << name_ << "(o);\n";
    });
  }
  hdr_ << "// Definition " << Position() << "\n";
  hdr_ << template_decl() << "\n";
  hdr_ << "class " << gen_name_ << " : public P {\n";
  hdr_ << "  static_assert(\n"
       << "      std::is_same<" << name_ << ", D>::value,\n"
       << "      \"Use this class as direct base for " << name_ << ".\");\n";
  hdr_ << "  static_assert(\n"
       << "      std::is_same<" << super_->name() << ", P>::value,\n"
       << "      \"Pass in " << super_->name()
       << " as second template parameter for " << gen_name_ << ".\");\n\n";
  hdr_ << " public: \n";
  hdr_ << "  using Super = P;\n";
  hdr_ << "  using TorqueGeneratedClass = " << gen_name_ << "<D,P>;\n\n";
  if (!type_->ShouldExport() && !type_->IsExtern()) {
    hdr_ << " protected: // not extern or @export\n";
  }
  for (const Field& f : type_->fields()) {
    CurrentSourcePosition::Scope scope(f.pos);
    std::vector<const Field*> struct_fields;
    GenerateFieldAccessors(f, struct_fields);
  }
  if (!type_->ShouldExport() && !type_->IsExtern()) {
    hdr_ << " public:\n";
  }

  std::vector<cpp::TemplateParameter> templateArgs = {
      cpp::TemplateParameter("D"), cpp::TemplateParameter("P")};
  cpp::Class c(std::move(templateArgs), gen_name_);

  if (type_->ShouldGeneratePrint()) {
    hdr_ << "  DECL_PRINTER(" << name_ << ")\n\n";
  }

  if (type_->ShouldGenerateVerify()) {
    IfDefScope hdr_scope(hdr_, "VERIFY_HEAP");
    // V8_EXPORT_PRIVATE void Verify(Isolate*);
    cpp::Function f(&c, name_ + "Verify");
    f.SetExport();
    f.SetReturnType("void");
    f.AddParameter("Isolate*", "isolate");
    f.PrintDeclaration(hdr_);

    IfDefScope impl_scope(impl_, "VERIFY_HEAP");
    impl_ << "\ntemplate <>\n";
    impl_ << "void " << gen_name_I_ << "::" << name_
          << "Verify(Isolate* isolate) {\n";
    impl_ << "  TorqueGeneratedClassVerifiers::" << name_ << "Verify(Cast<"
          << name_
          << ">(*this), "
             "isolate);\n";
    impl_ << "}\n\n";
    impl_ << "\n";
  }

  hdr_ << "\n";
  ClassFieldOffsetGenerator g(hdr_, inl_, type_, gen_name_,
                              type_->GetSuperClass());
  for (const auto& f : type_->fields()) {
    CurrentSourcePosition::Scope scope(f.pos);
    g.RecordOffsetFor(f);
  }
  g.Finish();
  hdr_ << "\n";

  auto index_fields = GetOrderedUniqueIndexFields(*type_);

  if (!index_fields.has_value()) {
    hdr_ << "  // SizeFor implementations not generated due to complex array "
            "lengths\n\n";

    const Field& last_field = type_->LastField();
    std::string last_field_item_size =
        std::get<1>(*SizeOf(last_field.name_and_type.type));

    // int AllocatedSize() const
    {
      cpp::Function f =
          cpp::Function::DefaultGetter("int", &c, "AllocatedSize");
      f.PrintDeclaration(hdr_);

      f.PrintDefinition(inl_, [&](std::ostream& stream) {
        stream << "  auto slice = "
               << Callable::PrefixNameForCCOutput(
                      type_->GetSliceMacroName(last_field))
               << "(*static_cast<const D*>(this));\n";
        stream << "  return static_cast<int>(std::get<1>(slice)) + "
               << last_field_item_size
               << " * static_cast<int>(std::get<2>(slice));\n";
      });
    }
  } else if (type_->ShouldGenerateBodyDescriptor() ||
             (!type_->IsAbstract() &&
              !type_->IsSubtypeOf(TypeOracle::GetJSObjectType()))) {
    cpp::Function f(&c, "SizeFor");
    f.SetReturnType("int32_t");
    f.SetFlags(cpp::Function::kStatic | cpp::Function::kConstexpr |
               cpp::Function::kV8Inline);
    for (const Field& field : *index_fields) {
      f.AddParameter("int", field.name_and_type.name);
    }
    f.PrintInlineDefinition(hdr_, [&](std::ostream& stream) {
      if (index_fields->empty()) {
        stream << "    DCHECK(kHeaderSize == kSize && kHeaderSize == "
               << *type_->size().SingleValue() << ");\n";
      }
      stream << "    int32_t size = kHeaderSize;\n";
      for (const Field& field : type_->ComputeAllFields()) {
        if (field.index) {
          auto index_name_and_type =
              *ExtractSimpleFieldArraySize(*type_, field.index->expr);
          stream << "    size += " << index_name_and_type.name << " * "
                 << std::get<0>(field.GetFieldSizeInformation()) << ";\n";
        }
      }
      if (type_->size().Alignment() < TargetArchitecture::TaggedSize()) {
        stream << "    size = OBJECT_POINTER_ALIGN(size);\n";
      }
      stream << "    return size;\n";
    });

    // V8_INLINE int32_t AllocatedSize() const
    {
      cpp::Function allocated_size_f =
          cpp::Function::DefaultGetter("int32_t", &c, "AllocatedSize");
      allocated_size_f.SetFlag(cpp::Function::kV8Inline);
      allocated_size_f.PrintInlineDefinition(hdr_, [&](std::ostream& stream) {
        stream << "    return SizeFor(";
        bool first = true;
        for (const auto& field : *index_fields) {
          if (!first) stream << ", ";
          stream << "this->" << field.name_and_type.name << "()";
          first = false;
        }
        stream << ");\n";
      });
    }
  }

  hdr_ << "  friend class Factory;\n\n";

  GenerateClassConstructors();

  hdr_ << "};\n\n";

  if (type_->ShouldGenerateFullClassDefinition()) {
    // If this class extends from another class which is defined in the same tq
    // file, and that other class doesn't generate a full class definition, then
    // the resulting .inc file would be uncompilable due to ordering
    // requirements: the generated file must go before the hand-written
    // definition of the base class, but it must also go after that same
    // hand-written definition.
    std::optional<const ClassType*> parent = type_->parent()->ClassSupertype();
    while (parent) {
      if ((*parent)->ShouldGenerateCppClassDefinitions() &&
          !(*parent)->ShouldGenerateFullClassDefinition() &&
          (*parent)->AttributedToFile() == type_->AttributedToFile()) {
        Error("Exported ", *type_,
              " cannot be in the same file as its parent extern ", **parent);
      }
      parent = (*parent)->parent()->ClassSupertype();
    }

    GenerateClassExport(type_, hdr_, inl_);
  }
}

void CppClassGenerator::GenerateCppObjectDefinitionAsserts() {
  impl_ << "// Definition " << Position() << "\n"
        << "class " << gen_name_ << "Asserts {\n";

  ClassFieldOffsetGenerator g(impl_, impl_, type_, gen_name_,
                              type_->GetSuperClass(), false);
  for (const auto& f : type_->fields()) {
    CurrentSourcePosition::Scope scope(f.pos);
    g.RecordOffsetFor(f);
  }
  g.Finish();
  impl_ << "\n";

  for (const auto& f : type_->fields()) {
    std::string field_offset =
        "k" + CamelifyString(f.name_and_type.name) + "Offset";
    impl_ << "  static_assert(" << field_offset << " == " << name_
          << "::" << field_offset << ",\n"
          << "                \"Values of " << name_ << "::" << field_offset
          << " defined in Torque and C++ do not match\");\n";
  }
  if (!type_->IsAbstract() && type_->HasStaticSize()) {
    impl_ << "  static_assert(kSize == " << name_ << "::kSize);\n";
  }

  impl_ << "};\n\n";
}

void CppClassGenerator::GenerateCppObjectLayoutDefinitionAsserts() {
  impl_ << "// Definition " << Position() << "\n"
        << "class " << gen_name_ << "Asserts {\n";

  ClassFieldOffsetGenerator g(impl_, impl_, type_, gen_name_,
                              type_->GetSuperClass(), false);
  for (const auto& f : type_->fields()) {
    CurrentSourcePosition::Scope scope(f.pos);
    g.RecordOffsetFor(f);
  }
  g.Finish();
  impl_ << "\n";

  for (const auto& f : type_->fields()) {
    std::string field_offset =
        "k" + CamelifyString(f.name_and_type.name) + "Offset";
    std::string cpp_field_offset =
        f.index.has_value()
            ? "OFFSET_OF_DATA_START(" + name_ + ")"
            : "offsetof(" + name_ + ", " + f.name_and_type.name + "_)";
    impl_ << "  static_assert(" << field_offset << " == " << cpp_field_offset
          << ",\n"
          << "                \"Value of " << name_ << "::" << field_offset
          << " defined in Torque and offset of field " << name_
          << "::" << f.name_and_type.name << " in C++ do not match\");\n";
  }
  if (!type_->IsAbstract() && type_->HasStaticSize()) {
    impl_ << "  static_assert(kSize == sizeof(" + name_ + "));\n";
  }

  impl_ << "};\n\n";
}

SourcePosition CppClassGenerator::Position() { return type_->GetPosition(); }

void CppClassGenerator::GenerateClassConstructors() {
  const ClassType* typecheck_type = type_;
  while (typecheck_type->IsShape()) {
    typecheck_type = typecheck_type->GetSuperClass();

    // Shapes have already been checked earlier to inherit from JSObject, so we
    // should have found an appropriate type.
    DCHECK(typecheck_type);
  }

  hdr_ << "  template <class DAlias = D>\n";
  hdr_ << "  constexpr " << gen_name_ << "() : P() {\n";
  hdr_ << "    static_assert(\n";
  hdr_ << "        std::is_base_of<" << gen_name_ << ", DAlias>::value,\n";
  hdr_ << "        \"class " << gen_name_
       << " should be used as direct base for " << name_ << ".\");\n";
  hdr_ << "  }\n\n";

  hdr_ << " protected:\n";
  hdr_ << "  inline explicit constexpr " << gen_name_
       << "(Address ptr, typename P::SkipTypeCheckTag\n)";
  hdr_ << "    : P(ptr, typename P::SkipTypeCheckTag{}) {}\n";
  hdr_ << "  inline explicit " << gen_name_ << "(Address ptr);\n";

  inl_ << "template<class D, class P>\n";
  inl_ << "inline " << gen_name_T_ << "::" << gen_name_ << "(Address ptr)\n";
  inl_ << "    : P(ptr) {\n";
  inl_ << "  SLOW_DCHECK(Is" << typecheck_type->name()
       << "_NonInline(*this));\n";
  inl_ << "}\n";
}

namespace {
std::string GenerateRuntimeTypeCheck(const Type* type,
                                     const std::string& value) {
  bool maybe_object = !type->IsSubtypeOf(TypeOracle::GetStrongTaggedType());
  std::stringstream type_check;
  bool at_start = true;
  // If weak pointers are allowed, then start by checking for a cleared value.
  if (maybe_object) {
    type_check << value << ".IsCleared()";
    at_start = false;
  }
  for (const TypeChecker& runtime_type : type->GetTypeCheckers()) {
    if (!at_start) type_check << " || ";
    at_start = false;
    if (maybe_object) {
      bool strong = runtime_type.weak_ref_to.empty();
      if (strong && runtime_type.type == WEAK_HEAP_OBJECT) {
        // Rather than a generic Weak<T>, this is the basic type WeakHeapObject.
        // We can't validate anything more about the type of the object pointed
        // to, so just check that it's weak.
        type_check << value << ".IsWeak()";
      } else {
        type_check << "(" << (strong ? "!" : "") << value << ".IsWeak() && Is"
                   << (strong ? runtime_type.type : runtime_type.weak_ref_to)
                   << "(" << value << ".GetHeapObjectOrSmi()))";
      }
    } else {
      type_check << "Is" << runtime_type.type << "(" << value << ")";
    }
  }
  return type_check.str();
}

void GenerateBoundsDCheck(std::ostream& os, const std::string& index,
                          const ClassType* type, const Field& f) {
  os << "  DCHECK_GE(" << index << ", 0);\n";
  std::string length_expression;
  if (std::optional<NameAndType> array_length =
          ExtractSimpleFieldArraySize(*type, f.index->expr)) {
    length_expression = "this ->" + array_length->name + "()";
  } else {
    // The length is element 2 in the flattened field slice.
    length_expression =
        "static_cast<int>(std::get<2>(" +
        Callable::PrefixNameForCCOutput(type->GetSliceMacroName(f)) +
        "(*static_cast<const D*>(this))))";
  }
  os << "  DCHECK_LT(" << index << ", " << length_expression << ");\n";
}

bool CanGenerateFieldAccessors(const Type* field_type) {
  // float64_or_hole should be treated like float64. For now, we don't need it.
  // TODO(v8:10391) Generate accessors for external pointers.
  return field_type != TypeOracle::GetVoidType() &&
         field_type != TypeOracle::GetFloat64OrHoleType() &&
         !field_type->IsSubtypeOf(TypeOracle::GetExternalPointerType()) &&
         !field_type->IsSubtypeOf(TypeOracle::GetTrustedPointerType()) &&
         !field_type->IsSubtypeOf(TypeOracle::GetProtectedPointerType());
}
}  // namespace

// TODO(sigurds): Keep in sync with DECL_ACCESSORS and ACCESSORS macro.
void CppClassGenerator::GenerateFieldAccessors(
    const Field& class_field, std::vector<const Field*>& struct_fields) {
  const Field& innermost_field =
      struct_fields.empty() ? class_field : *struct_fields.back();
  const Type* field_type = innermost_field.name_and_type.type;
  if (!CanGenerateFieldAccessors(field_type)) return;

  if (const StructType* struct_type = StructType::DynamicCast(field_type)) {
    struct_fields.resize(struct_fields.size() + 1);
    for (const Field& struct_field : struct_type->fields()) {
      struct_fields[struct_fields.size() - 1] = &struct_field;
      GenerateFieldAccessors(class_field, struct_fields);
    }
    struct_fields.resize(struct_fields.size() - 1);
    return;
  }

  bool indexed = class_field.index && !class_field.index->optional;
  std::string type_name = GetTypeNameForAccessor(innermost_field);
  bool can_contain_heap_objects = CanContainHeapObjects(field_type);

  // Assemble an accessor name by accumulating together all of the nested field
  // names.
  std::string name = class_field.name_and_type.name;
  for (const Field* nested_struct_field : struct_fields) {
    name += "_" + nested_struct_field->name_and_type.name;
  }

  // Generate declarations in header.
  if (can_contain_heap_objects && !field_type->IsClassType() &&
      !field_type->IsStructType() &&
      field_type != TypeOracle::GetObjectType()) {
    hdr_ << "  // Torque type: " << field_type->ToString() << "\n";
  }

  std::vector<cpp::TemplateParameter> templateParameters = {
      cpp::TemplateParameter("D"), cpp::TemplateParameter("P")};
  cpp::Class owner(std::move(templateParameters), gen_name_);

  // getter
  {
    auto getter = cpp::Function::DefaultGetter(type_name, &owner, name);
    if (indexed) {
      getter.AddParameter("int", "i");
    }
    const char* tag_argument;
    switch (class_field.synchronization) {
      case FieldSynchronization::kNone:
        tag_argument = "";
        break;
      case FieldSynchronization::kRelaxed:
        getter.AddParameter("RelaxedLoadTag");
        tag_argument = ", kRelaxedLoad";
        break;
      case FieldSynchronization::kAcquireRelease:
        getter.AddParameter("AcquireLoadTag");
        tag_argument = ", kAcquireLoad";
        break;
    }

    getter.PrintDeclaration(hdr_);

    // For tagged data, generate the extra getter that derives an
    // PtrComprCageBase from the current object's pointer.
    if (can_contain_heap_objects) {
      getter.PrintDefinition(inl_, [&](auto& stream) {
        stream
            << "  PtrComprCageBase cage_base = GetPtrComprCageBase(*this);\n";
        stream << "  return " << gen_name_ << "::" << name << "(cage_base"
               << (indexed ? ", i" : "") << tag_argument << ");\n";
      });

      getter.InsertParameter(0, "PtrComprCageBase", "cage_base");
      getter.PrintDeclaration(hdr_);
    }

    getter.PrintDefinition(inl_, [&](auto& stream) {
      EmitLoadFieldStatement(stream, class_field, struct_fields);
      stream << "  return value;\n";
    });
  }

  // setter
  {
    auto setter = cpp::Function::DefaultSetter(
        &owner, std::string("set_") + name, type_name, "value");
    if (indexed) {
      setter.InsertParameter(0, "int", "i");
    }
    switch (class_field.synchronization) {
      case FieldSynchronization::kNone:
        break;
      case FieldSynchronization::kRelaxed:
        setter.AddParameter("RelaxedStoreTag");
        break;
      case FieldSynchronization::kAcquireRelease:
        setter.AddParameter("ReleaseStoreTag");
        break;
    }
    if (can_contain_heap_objects) {
      setter.AddParameter("WriteBarrierMode", "mode", "UPDATE_WRITE_BARRIER");
    }
    setter.PrintDeclaration(hdr_);

    setter.PrintDefinition(inl_, [&](auto& stream) {
      EmitStoreFieldStatement(stream, class_field, struct_fields);
    });
  }

  hdr_ << "\n";
}

std::string CppClassGenerator::GetFieldOffsetForAccessor(const Field& f) {
  if (f.offset.has_value()) {
    return "k" + CamelifyString(f.name_and_type.name) + "Offset";
  }
  return CamelifyString(f.name_and_type.name) + "Offset()";
}

std::string CppClassGenerator::GetTypeNameForAccessor(const Field& f) {
  const Type* field_type = f.name_and_type.type;
  if (!field_type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
    const Type* constexpr_version = field_type->ConstexprVersion();
    if (!constexpr_version) {
      Error("Field accessor for ", type_->name(), ":: ", f.name_and_type.name,
            " cannot be generated because its type ", *field_type,
            " is neither a subclass of Object nor does the type have a "
            "constexpr "
            "version.")
          .Position(f.pos)
          .Throw();
    }
    return constexpr_version->GetGeneratedTypeName();
  }
  return field_type->TagglifiedCppTypeName();
}

bool CppClassGenerator::CanContainHeapObjects(const Type* t) {
  return t->IsSubtypeOf(TypeOracle::GetTaggedType()) &&
         !t->IsSubtypeOf(TypeOracle::GetSmiType());
}

void CppClassGenerator::EmitLoadFieldStatement(
    std::ostream& stream, const Field& class_field,
    std::vector<const Field*>& struct_fields) {
  const Field& innermost_field =
      struct_fields.empty() ? class_field : *struct_fields.back();
  const Type* field_type = innermost_field.name_and_type.type;
  std::string type_name = GetTypeNameForAccessor(innermost_field);
  const std::string class_field_size =
      std::get<1>(class_field.GetFieldSizeInformation());

  // field_offset contains both the offset from the beginning of the object to
  // the class field and the combined offsets of any nested struct fields
  // within, but not the index adjustment.
  std::string field_offset = GetFieldOffsetForAccessor(class_field);
  for (const Field* nested_struct_field : struct_fields) {
    field_offset += " + " + std::to_string(*nested_struct_field->offset);
  }

  std::string offset = field_offset;
  if (class_field.index) {
    const char* index = class_field.index->optional ? "0" : "i";
    GenerateBoundsDCheck(stream, index, type_, class_field);
    stream << "  int offset = " << field_offset << " + " << index << " * "
           << class_field_size << ";\n";
    offset = "offset";
  }

  stream << "  " << type_name << " value = ";

  if (!field_type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
    const char* load;
    switch (class_field.synchronization) {
      case FieldSynchronization::kNone:
        load = "ReadField";
        break;
      case FieldSynchronization::kRelaxed:
        load = "Relaxed_ReadField";
        break;
      case FieldSynchronization::kAcquireRelease:
        ReportError("Torque doesn't support @cppAcquireLoad on untagged data");
    }
    stream << "this->template " << load << "<" << type_name << ">(" << offset
           << ");\n";
  } else {
    const char* load;
    switch (class_field.synchronization) {
      case FieldSynchronization::kNone:
        load = "load";
        break;
      case FieldSynchronization::kRelaxed:
        load = "Relaxed_Load";
        break;
      case FieldSynchronization::kAcquireRelease:
        load = "Acquire_Load";
        break;
    }
    bool is_smi = field_type->IsSubtypeOf(TypeOracle::GetSmiType());
    const std::string load_type = is_smi ? "Smi" : type_name;
    const char* postfix = is_smi ? ".value()" : "";
    const char* optional_cage_base = is_smi ? "" : "cage_base, ";

    stream << "TaggedField<" << load_type << ">::" << load << "("
           << optional_cage_base << "*this, " << offset << ")" << postfix
           << ";\n";
  }

  if (CanContainHeapObjects(field_type)) {
    stream << "  DCHECK(" << GenerateRuntimeTypeCheck(field_type, "value")
           << ");\n";
  }
}

void CppClassGenerator::EmitStoreFieldStatement(
    std::ostream& stream, const Field& class_field,
    std::vector<const Field*>& struct_fields) {
  const Field& innermost_field =
      struct_fields.empty() ? class_field : *struct_fields.back();
  const Type* field_type = innermost_field.name_and_type.type;
  std::string type_name = GetTypeNameForAccessor(innermost_field);
  const std::string class_field_size =
      std::get<1>(class_field.GetFieldSizeInformation());

  // field_offset contains both the offset from the beginning of the object to
  // the class field and the combined offsets of any nested struct fields
  // within, but not the index adjustment.
  std::string field_offset = GetFieldOffsetForAccessor(class_field);
  for (const Field* nested_struct_field : struct_fields) {
    field_offset += " + " + std::to_string(*nested_struct_field->offset);
  }

  std::string offset = field_offset;
  if (class_field.index) {
    const char* index = class_field.index->optional ? "0" : "i";
    GenerateBoundsDCheck(stream, index, type_, class_field);
    stream << "  int offset = " << field_offset << " + " << index << " * "
           << class_field_size << ";\n";
    offset = "offset";
  }

  if (!field_type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
    const char* store;
    switch (class_field.synchronization) {
      case FieldSynchronization::kNone:
        store = "WriteField";
        break;
      case FieldSynchronization::kRelaxed:
        store = "Relaxed_WriteField";
        break;
      case FieldSynchronization::kAcquireRelease:
        ReportError("Torque doesn't support @cppReleaseStore on untagged data");
    }
    stream << "  this->template " << store << "<" << type_name << ">(" << offset
           << ", value);\n";
  } else {
    bool strong_pointer = field_type->IsSubtypeOf(TypeOracle::GetObjectType());
    bool is_smi = field_type->IsSubtypeOf(TypeOracle::GetSmiType());
    const char* write_macro;
    if (!strong_pointer) {
      if (class_field.synchronization ==
          FieldSynchronization::kAcquireRelease) {
        ReportError("Torque doesn't support @cppReleaseStore on weak fields");
      }
      write_macro = "RELAXED_WRITE_WEAK_FIELD";
    } else {
      switch (class_field.synchronization) {
        case FieldSynchronization::kNone:
          write_macro = "WRITE_FIELD";
          break;
        case FieldSynchronization::kRelaxed:
          write_macro = "RELAXED_WRITE_FIELD";
          break;
        case FieldSynchronization::kAcquireRelease:
          write_macro = "RELEASE_WRITE_FIELD";
          break;
      }
    }
    const std::string value_to_write = is_smi ? "Smi::FromInt(value)" : "value";

    if (!is_smi) {
      stream << "  SLOW_DCHECK("
             << GenerateRuntimeTypeCheck(field_type, "value") << ");\n";
    }
    stream << "  " << write_macro << "(*this, " << offset << ", "
           << value_to_write << ");\n";
    if (!is_smi) {
      stream << "  CONDITIONAL_WRITE_BARRIER(*this, " << offset
             << ", value, mode);\n";
    }
  }
}

void GenerateStructLayoutDescription(std::ostream& header,
                                     const StructType* type) {
  header << "struct TorqueGenerated" << CamelifyString(type->name())
         << "Offsets {\n";
  for (const Field& field : type->fields()) {
    header << "  static constexpr int k"
           << CamelifyString(field.name_and_type.name)
           << "Offset = " << *field.offset << ";\n";
  }
  header << "  static constexpr int kSize = " << type->PackedSize() << ";\n";
  header << "};\n\n";
}

}  // namespace

void ImplementationVisitor::GenerateClassDefinitions(
    const std::string& output_directory) {
  std::stringstream factory_header;
  std::stringstream factory_impl;
  std::string factory_basename = "factory";

  std::stringstream forward_declarations;
  std::string forward_declarations_filename = "class-forward-declarations.h";

  {
    factory_impl << "#include \"src/heap/factory-base.h\"\n";
    factory_impl << "#include \"src/heap/factory-base-inl.h\"\n";
    factory_impl << "#include \"src/heap/heap.h\"\n";
    factory_impl << "#include \"src/heap/heap-inl.h\"\n";
    factory_impl << "#include \"src/execution/isolate.h\"\n";
    factory_impl << "#include "
                    "\"src/objects/all-objects-inl.h\"\n\n";
    NamespaceScope factory_impl_namespaces(factory_impl, {"v8", "internal"});
    factory_impl << "\n";

    IncludeGuardScope include_guard(forward_declarations,
                                    forward_declarations_filename);
    NamespaceScope forward_declarations_namespaces(forward_declarations,
                                                   {"v8", "internal"});

    std::set<const StructType*, TypeLess> structs_used_in_classes;

    // Emit forward declarations.
    for (const ClassType* type : TypeOracle::GetClasses()) {
      CurrentSourcePosition::Scope position_activator(type->GetPosition());
      auto& streams = GlobalContext::GeneratedPerFile(type->AttributedToFile());
      std::ostream& header = streams.class_definition_headerfile;
      std::string name = type->ShouldGenerateCppClassDefinitions()
                             ? type->name()
                             : type->GetGeneratedTNodeTypeName();
      if (type->ShouldGenerateCppClassDefinitions()) {
        header << "class " << name << ";\n";
      }
      forward_declarations << "class " << name << ";\n";
    }

    for (const ClassType* type : TypeOracle::GetClasses()) {
      CurrentSourcePosition::Scope position_activator(type->GetPosition());
      auto& streams = GlobalContext::GeneratedPerFile(type->AttributedToFile());
      std::ostream& header = streams.class_definition_headerfile;
      std::ostream& inline_header = streams.class_definition_inline_headerfile;
      std::ostream& implementation = streams.class_definition_ccfile;

      if (type->ShouldGenerateCppClassDefinitions()) {
        CppClassGenerator g(type, header, inline_header, implementation);
        g.GenerateClass();
      } else if (type->ShouldGenerateCppObjectDefinitionAsserts()) {
        CppClassGenerator g(type, header, inline_header, implementation);
        g.GenerateCppObjectDefinitionAsserts();
      } else if (type->ShouldGenerateCppObjectLayoutDefinitionAsserts()) {
        CppClassGenerator g(type, header, inline_header, implementation);
        g.GenerateCppObjectLayoutDefinitionAsserts();
      }
      for (const Field& f : type->fields()) {
        const Type* field_type = f.name_and_type.type;
        if (auto field_as_struct = field_type->StructSupertype()) {
          structs_used_in_classes.insert(*field_as_struct);
        }
      }
      if (type->ShouldGenerateFactoryFunction()) {
        std::string return_type =
            type->HandlifiedCppTypeName(Type::HandleKind::kIndirect);
        std::string function_name = "New" + type->name();
        std::stringstream parameters;
        for (const Field& f : type->ComputeAllFields()) {
          if (f.name_and_type.name == "map") continue;
          if (f.name_and_type.name == "self_indirect_pointer") continue;
          if (!f.index) {
            std::string type_string =
                f.name_and_type.type->HandlifiedCppTypeName(
                    Type::HandleKind::kDirect);
            parameters << type_string << " " << f.name_and_type.name << ", ";
          }
        }
        parameters << "AllocationType allocation_type";

        factory_header << return_type << " " << function_name << "("
                       << parameters.str() << ");\n";
        factory_impl << "template <typename Impl>\n";
        factory_impl << return_type
                     << " TorqueGeneratedFactory<Impl>::" << function_name
                     << "(" << parameters.str() << ") {\n";

        factory_impl << "  int size = ";
        const ClassType* super = type->GetSuperClass();
        std::string gen_name = "TorqueGenerated" + type->name();
        std::string gen_name_T =
            gen_name + "<" + type->name() + ", " + super->name() + ">";
        factory_impl << gen_name_T << "::SizeFor(";

        bool first = true;
        auto index_fields = GetOrderedUniqueIndexFields(*type);
        CHECK(index_fields.has_value());
        for (const auto& index_field : *index_fields) {
          if (!first) {
            factory_impl << ", ";
          }
          factory_impl << index_field.name_and_type.name;
          first = false;
        }

        factory_impl << ");\n";
        factory_impl << "  Tagged<Map> map = factory()->read_only_roots()."
                     << SnakeifyString(type->name()) << "_map();\n";
        factory_impl << "  Tagged<HeapObject> raw_object =\n";
        factory_impl << "    factory()->AllocateRawWithImmortalMap(size, "
                        "allocation_type, map);\n";
        factory_impl << "  " << type->TagglifiedCppTypeName()
                     << " result = Cast<"
                     << type->GetConstexprGeneratedTypeName()
                     << ">(raw_object);\n";
        factory_impl << "  DisallowGarbageCollection no_gc;\n";
        factory_impl << "  WriteBarrierMode write_barrier_mode =\n"
                     << "     allocation_type == AllocationType::kYoung\n"
                     << "     ? SKIP_WRITE_BARRIER : UPDATE_WRITE_BARRIER;\n"
                     << "  USE(write_barrier_mode);\n";

        for (const Field& f : type->ComputeAllFields()) {
          if (f.name_and_type.name == "map") continue;
          if (f.name_and_type.name == "self_indirect_pointer") {
            factory_impl << "  "
```