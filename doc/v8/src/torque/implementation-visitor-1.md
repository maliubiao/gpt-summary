Response: The user wants me to summarize the functionality of a C++ source code file related to the Torque compiler in V8. This is the second part of a four-part breakdown. I need to focus on the code provided in this segment and its role.

Looking at the code, it seems to be handling the implementation logic for various language constructs in Torque, such as:

- **Class Instantiation:**  Processing `NewExpression` to allocate and initialize class instances.
- **Control Flow:** Handling `BreakStatement`, `ContinueStatement`, and `ForLoopStatement`.
- **Code Generation:**  The `GenerateImplementation` function suggests outputting generated C++ code.
- **Function/Macro Calls:**  The `GenerateMacroFunctionDeclaration` and `GenerateFunction` functions are involved in generating C++ function declarations. The `LookupCallable` and `GenerateCall` functions handle resolving and generating calls to Torque callables (builtins, macros, runtime functions).
- **Memory Access:** The code deals with accessing fields of objects (including structs, classes, and bitfields) using functions like `GenerateFieldAccess`, `ProjectStructField`, and `GenerateSetBitField`. It also handles loading and storing values in memory using `GenerateFetchFromLocation` and `GenerateAssignToLocation`.
- **Pointers:**  `GeneratePointerCall` handles calling functions through function pointers.

Considering the context of the previous and likely subsequent parts, this part of `implementation-visitor.cc` seems to be responsible for translating higher-level Torque language constructs into lower-level operations, often involving calls to generated C++ functions or emitting specific instructions.

Regarding the relationship with JavaScript, Torque is used to implement built-in JavaScript functionality. The code here is generating the C++ that will eventually be part of V8, the JavaScript engine.

For example, when a JavaScript `new` expression is executed, like `new Date()`, the Torque compiler might use the logic within the `Visit(NewExpression* expr)` function (or related functions) to generate the C++ code that allocates memory for a `Date` object and calls its constructor.

Let's formulate the summary.这个C++源代码文件 (`v8/src/torque/implementation-visitor.cc`) 的第二部分主要负责 **实现 Torque 语言中各种语句和表达式的编译逻辑，并生成相应的底层代码（通常是 CodeStubAssembler 指令或者 C++ 代码）**。它在 Torque 编译器的执行过程中，遍历抽象语法树 (AST)，并根据不同的语法节点执行相应的代码生成操作。

具体来说，这部分代码涵盖了以下功能：

* **类实例化 (`NewExpression`)**:  处理 `new` 关键字创建对象的逻辑。它负责查找类的定义，处理初始化参数，并生成调用内存分配和初始化的代码。
* **控制流语句 (`BreakStatement`, `ContinueStatement`, `ForLoopStatement`)**:  实现 `break`、`continue` 和 `for` 循环等控制流语句的编译逻辑，生成相应的跳转指令。
* **代码生成 (`GenerateImplementation`)**:  负责将编译后的结果写入到不同的输出文件中，例如 `.cc`、`.h` 和 `.inc` 文件。
* **函数和宏的生成和调用 (`GenerateMacroFunctionDeclaration`, `GenerateFunction`, `LookupCallable`, `GenerateCall`)**:  定义了如何生成 C++ 函数声明，以及如何查找和生成对 Torque 定义的函数（包括内置函数、宏和运行时函数）的调用代码。
* **内存访问 (`GenerateFieldAccess`, `ProjectStructField`, `GenerateSetBitField`, `GenerateFetchFromLocation`, `GenerateAssignToLocation`)**:  处理对对象字段的访问和赋值操作，包括结构体、类和位域。它负责计算偏移量，并生成相应的加载和存储指令。
* **指针调用 (`GeneratePointerCall`)**:  处理通过函数指针调用函数的情况。
* **类型推断和转换**:  在函数调用等场景中，进行类型检查和隐式类型转换。

**与 JavaScript 的关系：**

Torque 用于实现 V8 JavaScript 引擎的内置功能。这部分代码生成的 C++ 代码最终会成为 V8 引擎的一部分。

举例来说，当 JavaScript 代码执行 `new Date()` 时，Torque 编译器可能会使用这部分代码中的逻辑来生成相应的 C++ 代码，用于：

1. **分配内存**: 调用类似 `AllocateFromNew` 的函数来为 `Date` 对象分配内存。
2. **初始化对象**:  调用 `Date` 类的构造函数（可能也是用 Torque 定义的），并传递必要的参数（例如，Map 对象）。
3. **类型转换**: 在传递参数时，可能需要进行类型转换，确保 JavaScript 的值能够正确地传递给 C++ 的构造函数。

例如，在 JavaScript 中创建 `Date` 对象的代码：

```javascript
const now = new Date();
```

在 Torque 编译过程中，`Visit(NewExpression* expr)` 函数可能会被调用来处理这个 `new Date()` 表达式。它会查找 `Date` 类的定义，提取初始化参数，并生成类似以下的 C++ 代码（简化示例）：

```c++
// ... (获取 Date 类的 Map) ...
v8::Object* date_object = AllocateFromNew(sizeof(v8::Date), date_map, false, false); // 分配内存
// ... (调用 Date 类的初始化函数，可能需要类型转换) ...
```

这里 `AllocateFromNew` 函数的调用就对应了 `ImplementationVisitor::Visit(NewExpression* expr)` 中生成的代码。`date_map` 变量的获取也可能涉及到调用 Torque 定义的内置函数。最终，这些生成的 C++ 代码会被编译进 V8 引擎，并在 JavaScript 代码执行时被调用。

总而言之，这部分 `implementation-visitor.cc` 的核心功能是将 Torque 代码转换为 V8 引擎能够执行的 C++ 代码，是连接 Torque 语言和 JavaScript 执行的桥梁。

### 提示词
```
这是目录为v8/src/torque/implementation-visitor.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
lass_type,
                " cannot be allocated with new (it's used for testing)");
  }

  InitializerResults initializer_results =
      VisitInitializerResults(class_type, expr->initializers);

  const Field& map_field = class_type->LookupField("map");
  if (*map_field.offset != 0) {
    ReportError("class initializers must have a map as first parameter");
  }
  const std::map<std::string, VisitResult>& initializer_fields =
      initializer_results.field_value_map;
  auto it_object_map = initializer_fields.find(map_field.name_and_type.name);
  VisitResult object_map;
  if (class_type->IsExtern()) {
    if (it_object_map == initializer_fields.end()) {
      ReportError("Constructor for ", class_type->name(),
                  " needs Map argument!");
    }
    object_map = it_object_map->second;
  } else {
    if (it_object_map != initializer_fields.end()) {
      ReportError(
          "Constructor for ", class_type->name(),
          " must not specify Map argument; it is automatically inserted.");
    }
    Arguments get_struct_map_arguments;
    get_struct_map_arguments.parameters.push_back(
        VisitResult(TypeOracle::GetConstexprInstanceTypeType(),
                    CapifyStringWithUnderscores(class_type->name()) + "_TYPE"));
    object_map = GenerateCall(
        QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING}, "GetInstanceTypeMap"),
        get_struct_map_arguments, {}, false);
    CurrentSourcePosition::Scope current_pos(expr->pos);
    initializer_results.names.insert(initializer_results.names.begin(),
                                     MakeNode<Identifier>("map"));
    initializer_results.field_value_map[map_field.name_and_type.name] =
        object_map;
  }

  CheckInitializersWellformed(class_type->name(),
                              class_type->ComputeAllFields(),
                              expr->initializers, !class_type->IsExtern());

  LayoutForInitialization layout =
      GenerateLayoutForInitialization(class_type, initializer_results);

  Arguments allocate_arguments;
  allocate_arguments.parameters.push_back(layout.size);
  allocate_arguments.parameters.push_back(object_map);
  allocate_arguments.parameters.push_back(
      GenerateBoolConstant(expr->pretenured));
  allocate_arguments.parameters.push_back(
      GenerateBoolConstant(expr->clear_padding));
  VisitResult allocate_result = GenerateCall(
      QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING}, "AllocateFromNew"),
      allocate_arguments, {class_type}, false);
  DCHECK(allocate_result.IsOnStack());

  InitializeClass(class_type, allocate_result, initializer_results, layout);

  return stack_scope.Yield(GenerateCall(
      "%RawDownCast", Arguments{{allocate_result}, {}}, {class_type}));
}

const Type* ImplementationVisitor::Visit(BreakStatement* stmt) {
  std::optional<Binding<LocalLabel>*> break_label =
      TryLookupLabel(kBreakLabelName);
  if (!break_label) {
    ReportError("break used outside of loop");
  }
  assembler().Goto((*break_label)->block);
  return TypeOracle::GetNeverType();
}

const Type* ImplementationVisitor::Visit(ContinueStatement* stmt) {
  std::optional<Binding<LocalLabel>*> continue_label =
      TryLookupLabel(kContinueLabelName);
  if (!continue_label) {
    ReportError("continue used outside of loop");
  }
  assembler().Goto((*continue_label)->block);
  return TypeOracle::GetNeverType();
}

const Type* ImplementationVisitor::Visit(ForLoopStatement* stmt) {
  BlockBindings<LocalValue> loop_bindings(&ValueBindingsManager::Get());

  if (stmt->var_declaration) Visit(*stmt->var_declaration, &loop_bindings);

  Block* body_block = assembler().NewBlock(assembler().CurrentStack());
  Block* exit_block = assembler().NewBlock(assembler().CurrentStack());

  Block* header_block = assembler().NewBlock();
  assembler().Goto(header_block);
  assembler().Bind(header_block);

  // The continue label is where "continue" statements jump to. If no action
  // expression is provided, we jump directly to the header.
  Block* continue_block = header_block;

  // The action label is only needed when an action expression was provided.
  Block* action_block = nullptr;
  if (stmt->action) {
    action_block = assembler().NewBlock();

    // The action expression needs to be executed on a continue.
    continue_block = action_block;
  }

  if (stmt->test) {
    GenerateExpressionBranch(*stmt->test, body_block, exit_block);
  } else {
    assembler().Goto(body_block);
  }

  assembler().Bind(body_block);
  {
    BreakContinueActivator activator(exit_block, continue_block);
    const Type* body_result = Visit(stmt->body);
    if (body_result != TypeOracle::GetNeverType()) {
      assembler().Goto(continue_block);
    }
  }

  if (stmt->action) {
    assembler().Bind(action_block);
    const Type* action_result = Visit(*stmt->action);
    if (action_result != TypeOracle::GetNeverType()) {
      assembler().Goto(header_block);
    }
  }

  assembler().Bind(exit_block);
  return TypeOracle::GetVoidType();
}

VisitResult ImplementationVisitor::Visit(SpreadExpression* expr) {
  ReportError(
      "spread operators are only currently supported in indexed class field "
      "initialization expressions");
}

void ImplementationVisitor::GenerateImplementation(const std::string& dir) {
  for (SourceId file : SourceFileMap::AllSources()) {
    std::string base_filename =
        dir + "/" + SourceFileMap::PathFromV8RootWithoutExtension(file);
    GlobalContext::PerFileStreams& streams =
        GlobalContext::GeneratedPerFile(file);

    std::string csa_cc = streams.csa_ccfile.str();
    // Insert missing builtin includes where the marker is.
    {
      auto pos = csa_cc.find(BuiltinIncludesMarker);
      CHECK_NE(pos, std::string::npos);
      std::string includes;
      for (const SourceId& include : streams.required_builtin_includes) {
        std::string include_file =
            SourceFileMap::PathFromV8RootWithoutExtension(include);
        includes += "#include \"torque-generated/";
        includes += include_file;
        includes += "-tq-csa.h\"\n";
      }
      csa_cc.replace(pos, strlen(BuiltinIncludesMarker), std::move(includes));
    }

    // TODO(torque-builder): Pass file directly.
    WriteFile(base_filename + "-tq-csa.cc", std::move(csa_cc));
    WriteFile(base_filename + "-tq-csa.h", streams.csa_headerfile.str());
    WriteFile(base_filename + "-tq.inc",
              streams.class_definition_headerfile.str());
    WriteFile(
        base_filename + "-tq-inl.inc",
        streams.class_definition_inline_headerfile_macro_declarations.str() +
            streams.class_definition_inline_headerfile_macro_definitions.str() +
            streams.class_definition_inline_headerfile.str());
    WriteFile(base_filename + "-tq.cc", streams.class_definition_ccfile.str());
  }

  WriteFile(dir + "/debug-macros.h", debug_macros_h_.str());
  WriteFile(dir + "/debug-macros.cc", debug_macros_cc_.str());
}

cpp::Function ImplementationVisitor::GenerateMacroFunctionDeclaration(
    Macro* macro) {
  return GenerateFunction(nullptr,
                          output_type_ == OutputType::kCC
                              ? macro->CCName()
                              : output_type_ == OutputType::kCCDebug
                                    ? macro->CCDebugName()
                                    : macro->ExternalName(),
                          macro->signature(), macro->parameter_names());
}

cpp::Function ImplementationVisitor::GenerateFunction(
    cpp::Class* owner, const std::string& name, const Signature& signature,
    const NameVector& parameter_names, bool pass_code_assembler_state,
    std::vector<std::string>* generated_parameter_names) {
  cpp::Function f(owner, name);
  f.SetInline(output_type_ == OutputType::kCC);

  // Set return type.
  // TODO(torque-builder): Consider an overload of SetReturnType that handles
  // this.
  if (signature.return_type->IsVoidOrNever()) {
    f.SetReturnType("void");
  } else if (output_type_ == OutputType::kCCDebug) {
    f.SetReturnType(std::string("Value<") +
                    signature.return_type->GetDebugType() + ">");
  } else if (output_type_ == OutputType::kCC) {
    f.SetReturnType(signature.return_type->GetRuntimeType());
  } else {
    DCHECK_EQ(output_type_, OutputType::kCSA);
    f.SetReturnType(signature.return_type->IsConstexpr()
                        ? signature.return_type->TagglifiedCppTypeName()
                        : signature.return_type->GetGeneratedTypeName());
  }

  bool ignore_first_parameter = true;
  if (output_type_ == OutputType::kCCDebug) {
    f.AddParameter("d::MemoryAccessor", "accessor");
  } else if (output_type_ == OutputType::kCSA && pass_code_assembler_state) {
    f.AddParameter("compiler::CodeAssemblerState*", "state_");
  } else {
    ignore_first_parameter = false;
  }

  // TODO(torque-builder): Consider an overload for AddParameter that handles
  // this.
  DCHECK_GE(signature.types().size(), parameter_names.size());
  for (std::size_t i = 0; i < signature.types().size(); ++i) {
    const Type* parameter_type = signature.types()[i];
    std::string type;
    if (output_type_ == OutputType::kCC) {
      type = parameter_type->GetRuntimeType();
    } else if (output_type_ == OutputType::kCCDebug) {
      type = parameter_type->GetDebugType();
    } else {
      DCHECK_EQ(output_type_, OutputType::kCSA);
      if (parameter_type->IsConstexpr()) {
        type = parameter_type->TagglifiedCppTypeName();
      } else {
        type = parameter_type->GetGeneratedTypeName();
      }
    }
    f.AddParameter(std::move(type),
                   ExternalParameterName(i < parameter_names.size()
                                             ? parameter_names[i]->value
                                             : std::to_string(i)));
  }

  for (const LabelDeclaration& label_info : signature.labels) {
    if (output_type_ == OutputType::kCC ||
        output_type_ == OutputType::kCCDebug) {
      ReportError("Macros that generate runtime code can't have label exits");
    }
    f.AddParameter("compiler::CodeAssemblerLabel*",
                   ExternalLabelName(label_info.name->value));
    size_t i = 0;
    for (const Type* type : label_info.types) {
      std::string generated_type_name;
      if (type->StructSupertype()) {
        generated_type_name = "\n#error no structs allowed in labels\n";
      } else {
        generated_type_name = "compiler::TypedCodeAssemblerVariable<";
        generated_type_name += type->GetGeneratedTNodeTypeName();
        generated_type_name += ">*";
      }
      f.AddParameter(generated_type_name,
                     ExternalLabelParameterName(label_info.name->value, i));
      ++i;
    }
  }

  if (generated_parameter_names) {
    *generated_parameter_names = f.GetParameterNames();
    if (ignore_first_parameter) {
      DCHECK(!generated_parameter_names->empty());
      generated_parameter_names->erase(generated_parameter_names->begin());
    }
  }
  return f;
}

namespace {

void FailCallableLookup(
    const std::string& reason, const QualifiedName& name,
    const TypeVector& parameter_types,
    const std::vector<Binding<LocalLabel>*>& labels,
    const std::vector<Signature>& candidates,
    const std::vector<std::pair<GenericCallable*, std::string>>
        inapplicable_generics) {
  std::stringstream stream;
  stream << "\n" << reason << ": \n  " << name << "(" << parameter_types << ")";
  if (!labels.empty()) {
    stream << " labels ";
    for (size_t i = 0; i < labels.size(); ++i) {
      stream << labels[i]->name() << "(" << labels[i]->parameter_types << ")";
    }
  }
  stream << "\ncandidates are:";
  for (const Signature& signature : candidates) {
    stream << "\n  " << name;
    PrintSignature(stream, signature, false);
  }
  if (!inapplicable_generics.empty()) {
    stream << "\nfailed to instantiate all of these generic declarations:";
    for (auto& failure : inapplicable_generics) {
      GenericCallable* generic = failure.first;
      const std::string& fail_reason = failure.second;
      stream << "\n  " << generic->name() << " defined at "
             << PositionAsString(generic->Position()) << ":\n    "
             << fail_reason << "\n";
    }
  }
  ReportError(stream.str());
}

Callable* GetOrCreateSpecialization(
    const SpecializationKey<GenericCallable>& key) {
  if (std::optional<Callable*> specialization =
          key.generic->GetSpecialization(key.specialized_types)) {
    return *specialization;
  }
  return DeclarationVisitor::SpecializeImplicit(key);
}

}  // namespace

std::optional<Binding<LocalValue>*> ImplementationVisitor::TryLookupLocalValue(
    const std::string& name) {
  return ValueBindingsManager::Get().TryLookup(name);
}

std::optional<Binding<LocalLabel>*> ImplementationVisitor::TryLookupLabel(
    const std::string& name) {
  return LabelBindingsManager::Get().TryLookup(name);
}

Binding<LocalLabel>* ImplementationVisitor::LookupLabel(
    const std::string& name) {
  std::optional<Binding<LocalLabel>*> label = TryLookupLabel(name);
  if (!label) ReportError("cannot find label ", name);
  return *label;
}

Block* ImplementationVisitor::LookupSimpleLabel(const std::string& name) {
  LocalLabel* label = LookupLabel(name);
  if (!label->parameter_types.empty()) {
    ReportError("label ", name,
                "was expected to have no parameters, but has parameters (",
                label->parameter_types, ")");
  }
  return label->block;
}

// Try to lookup a callable with the provided argument types. Do not report
// an error if no matching callable was found, but return false instead.
// This is used to test the presence of overloaded field accessors.
bool ImplementationVisitor::TestLookupCallable(
    const QualifiedName& name, const TypeVector& parameter_types) {
  return LookupCallable(name, Declarations::TryLookup(name), parameter_types,
                        {}, {}, true) != nullptr;
}

TypeArgumentInference ImplementationVisitor::InferSpecializationTypes(
    GenericCallable* generic, const TypeVector& explicit_specialization_types,
    const TypeVector& explicit_arguments) {
  std::vector<std::optional<const Type*>> all_arguments;
  const ParameterList& parameters = generic->declaration()->parameters;
  for (size_t i = 0; i < parameters.implicit_count; ++i) {
    std::optional<Binding<LocalValue>*> val =
        TryLookupLocalValue(parameters.names[i]->value);
    all_arguments.push_back(
        val ? (*val)->GetLocationReference(*val).ReferencedType()
            : std::nullopt);
  }
  for (const Type* explicit_argument : explicit_arguments) {
    all_arguments.push_back(explicit_argument);
  }
  return generic->InferSpecializationTypes(explicit_specialization_types,
                                           all_arguments);
}

template <class Container>
Callable* ImplementationVisitor::LookupCallable(
    const QualifiedName& name, const Container& declaration_container,
    const TypeVector& parameter_types,
    const std::vector<Binding<LocalLabel>*>& labels,
    const TypeVector& specialization_types, bool silence_errors) {
  Callable* result = nullptr;

  std::vector<Declarable*> overloads;
  std::vector<Signature> overload_signatures;
  std::vector<std::pair<GenericCallable*, std::string>> inapplicable_generics;
  for (auto* declarable : declaration_container) {
    if (GenericCallable* generic = GenericCallable::DynamicCast(declarable)) {
      TypeArgumentInference inference = InferSpecializationTypes(
          generic, specialization_types, parameter_types);
      if (inference.HasFailed()) {
        inapplicable_generics.push_back(
            std::make_pair(generic, inference.GetFailureReason()));
        continue;
      }
      overloads.push_back(generic);
      overload_signatures.push_back(
          DeclarationVisitor::MakeSpecializedSignature(
              SpecializationKey<GenericCallable>{generic,
                                                 inference.GetResult()}));
    } else if (Callable* callable = Callable::DynamicCast(declarable)) {
      overloads.push_back(callable);
      overload_signatures.push_back(callable->signature());
    }
  }
  // Indices of candidates in overloads/overload_signatures.
  std::vector<size_t> candidates;
  for (size_t i = 0; i < overloads.size(); ++i) {
    const Signature& signature = overload_signatures[i];
    if (IsCompatibleSignature(signature, parameter_types, labels.size())) {
      candidates.push_back(i);
    }
  }

  if (overloads.empty() && inapplicable_generics.empty()) {
    if (silence_errors) return nullptr;
    std::stringstream stream;
    stream << "no matching declaration found for " << name;
    ReportError(stream.str());
  } else if (candidates.empty()) {
    if (silence_errors) return nullptr;
    FailCallableLookup("cannot find suitable callable with name", name,
                       parameter_types, labels, overload_signatures,
                       inapplicable_generics);
  }

  auto is_better_candidate = [&](size_t a, size_t b) {
    return ParameterDifference(overload_signatures[a].GetExplicitTypes(),
                               parameter_types)
        .StrictlyBetterThan(ParameterDifference(
            overload_signatures[b].GetExplicitTypes(), parameter_types));
  };

  size_t best = *std::min_element(candidates.begin(), candidates.end(),
                                  is_better_candidate);
  // This check is contained in libstdc++'s std::min_element.
  DCHECK(!is_better_candidate(best, best));
  for (size_t candidate : candidates) {
    if (candidate != best && !is_better_candidate(best, candidate)) {
      std::vector<Signature> candidate_signatures;
      candidate_signatures.reserve(candidates.size());
      for (size_t i : candidates) {
        candidate_signatures.push_back(overload_signatures[i]);
      }
      FailCallableLookup("ambiguous callable ", name, parameter_types, labels,
                         candidate_signatures, inapplicable_generics);
    }
  }

  if (GenericCallable* generic =
          GenericCallable::DynamicCast(overloads[best])) {
    TypeArgumentInference inference = InferSpecializationTypes(
        generic, specialization_types, parameter_types);
    result = GetOrCreateSpecialization(
        SpecializationKey<GenericCallable>{generic, inference.GetResult()});
  } else {
    result = Callable::cast(overloads[best]);
  }

  size_t caller_size = parameter_types.size();
  size_t callee_size =
      result->signature().types().size() - result->signature().implicit_count;
  if (caller_size != callee_size &&
      !result->signature().parameter_types.var_args) {
    std::stringstream stream;
    stream << "parameter count mismatch calling " << *result << " - expected "
           << std::to_string(callee_size) << ", found "
           << std::to_string(caller_size);
    ReportError(stream.str());
  }

  return result;
}

template <class Container>
Callable* ImplementationVisitor::LookupCallable(
    const QualifiedName& name, const Container& declaration_container,
    const Arguments& arguments, const TypeVector& specialization_types) {
  return LookupCallable(name, declaration_container,
                        arguments.parameters.ComputeTypeVector(),
                        arguments.labels, specialization_types);
}

Method* ImplementationVisitor::LookupMethod(
    const std::string& name, const AggregateType* receiver_type,
    const Arguments& arguments, const TypeVector& specialization_types) {
  TypeVector types(arguments.parameters.ComputeTypeVector());
  types.insert(types.begin(), receiver_type);
  return Method::cast(LookupCallable({{}, name}, receiver_type->Methods(name),
                                     types, arguments.labels,
                                     specialization_types));
}

const Type* ImplementationVisitor::GetCommonType(const Type* left,
                                                 const Type* right) {
  const Type* common_type;
  if (IsAssignableFrom(left, right)) {
    common_type = left;
  } else if (IsAssignableFrom(right, left)) {
    common_type = right;
  } else {
    common_type = TypeOracle::GetUnionType(left, right);
  }
  common_type = common_type->NonConstexprVersion();
  return common_type;
}

VisitResult ImplementationVisitor::GenerateCopy(const VisitResult& to_copy) {
  if (to_copy.IsOnStack()) {
    return VisitResult(to_copy.type(),
                       assembler().Peek(to_copy.stack_range(), to_copy.type()));
  }
  return to_copy;
}

VisitResult ImplementationVisitor::Visit(StructExpression* expr) {
  StackScope stack_scope(this);

  auto& initializers = expr->initializers;
  std::vector<VisitResult> values;
  std::vector<const Type*> term_argument_types;
  values.reserve(initializers.size());
  term_argument_types.reserve(initializers.size());

  // Compute values and types of all initializer arguments
  for (const NameAndExpression& initializer : initializers) {
    VisitResult value = Visit(initializer.expression);
    values.push_back(value);
    term_argument_types.push_back(value.type());
  }

  // Compute and check struct type from given struct name and argument types
  const Type* type = TypeVisitor::ComputeTypeForStructExpression(
      expr->type, term_argument_types);
  if (const auto* struct_type = StructType::DynamicCast(type)) {
    CheckInitializersWellformed(struct_type->name(), struct_type->fields(),
                                initializers);

    // Implicitly convert values and thereby build the struct on the stack
    StackRange struct_range = assembler().TopRange(0);
    auto& fields = struct_type->fields();
    for (size_t i = 0; i < values.size(); i++) {
      values[i] =
          GenerateImplicitConvert(fields[i].name_and_type.type, values[i]);
      struct_range.Extend(values[i].stack_range());
    }

    return stack_scope.Yield(VisitResult(struct_type, struct_range));
  } else {
    const auto* bitfield_struct_type = BitFieldStructType::cast(type);
    CheckInitializersWellformed(bitfield_struct_type->name(),
                                bitfield_struct_type->fields(), initializers);

    // Create a zero and cast it to the desired bitfield struct type.
    VisitResult result{TypeOracle::GetConstInt32Type(), "0"};
    result = GenerateImplicitConvert(TypeOracle::GetInt32Type(), result);
    result = GenerateCall("Unsigned", Arguments{{result}, {}}, {});
    result = GenerateCall("%RawDownCast", Arguments{{result}, {}},
                          {bitfield_struct_type});

    // Set each field in the result. If these fields are constexpr, then all of
    // this initialization will end up reduced to a single value during TurboFan
    // optimization.
    auto& fields = bitfield_struct_type->fields();
    for (size_t i = 0; i < values.size(); i++) {
      values[i] =
          GenerateImplicitConvert(fields[i].name_and_type.type, values[i]);
      result = GenerateSetBitField(bitfield_struct_type, fields[i], result,
                                   values[i], /*starts_as_zero=*/true);
    }

    return stack_scope.Yield(result);
  }
}

VisitResult ImplementationVisitor::GenerateSetBitField(
    const Type* bitfield_struct_type, const BitField& bitfield,
    VisitResult bitfield_struct, VisitResult value, bool starts_as_zero) {
  GenerateCopy(bitfield_struct);
  GenerateCopy(value);
  assembler().Emit(
      StoreBitFieldInstruction{bitfield_struct_type, bitfield, starts_as_zero});
  return VisitResult(bitfield_struct_type, assembler().TopRange(1));
}

LocationReference ImplementationVisitor::GetLocationReference(
    Expression* location) {
  switch (location->kind) {
    case AstNode::Kind::kIdentifierExpression:
      return GetLocationReference(static_cast<IdentifierExpression*>(location));
    case AstNode::Kind::kFieldAccessExpression:
      return GetLocationReference(
          static_cast<FieldAccessExpression*>(location));
    case AstNode::Kind::kElementAccessExpression:
      return GetLocationReference(
          static_cast<ElementAccessExpression*>(location));
    case AstNode::Kind::kDereferenceExpression:
      return GetLocationReference(
          static_cast<DereferenceExpression*>(location));
    default:
      return LocationReference::Temporary(Visit(location), "expression");
  }
}

LocationReference ImplementationVisitor::GetLocationReference(
    FieldAccessExpression* expr) {
  return GenerateFieldAccess(GetLocationReference(expr->object),
                             expr->field->value, false, expr->field->pos);
}

LocationReference ImplementationVisitor::GenerateFieldAccess(
    LocationReference reference, const std::string& fieldname,
    bool ignore_stuct_field_constness, std::optional<SourcePosition> pos) {
  if (reference.IsVariableAccess() &&
      reference.variable().type()->StructSupertype()) {
    const StructType* type = *reference.variable().type()->StructSupertype();
    const Field& field = type->LookupField(fieldname);
    if (GlobalContext::collect_language_server_data() && pos.has_value()) {
      LanguageServerData::AddDefinition(*pos, field.pos);
    }
    if (GlobalContext::collect_kythe_data() && pos.has_value()) {
      KytheData::AddClassFieldUse(*pos, &field);
    }
    if (field.const_qualified) {
      VisitResult t_value = ProjectStructField(reference.variable(), fieldname);
      return LocationReference::Temporary(
          t_value, "for constant field '" + field.name_and_type.name + "'");
    } else {
      return LocationReference::VariableAccess(
          ProjectStructField(reference.variable(), fieldname));
    }
  }
  if (reference.IsTemporary() &&
      reference.temporary().type()->StructSupertype()) {
    if (GlobalContext::collect_language_server_data() && pos.has_value()) {
      const StructType* type = *reference.temporary().type()->StructSupertype();
      const Field& field = type->LookupField(fieldname);
      LanguageServerData::AddDefinition(*pos, field.pos);
    }
    return LocationReference::Temporary(
        ProjectStructField(reference.temporary(), fieldname),
        reference.temporary_description());
  }
  if (std::optional<const Type*> referenced_type = reference.ReferencedType()) {
    if ((*referenced_type)->IsBitFieldStructType()) {
      const BitFieldStructType* bitfield_struct =
          BitFieldStructType::cast(*referenced_type);
      const BitField& field = bitfield_struct->LookupField(fieldname);
      return LocationReference::BitFieldAccess(reference, field);
    }
    if (const auto type_wrapped_in_smi = Type::MatchUnaryGeneric(
            (*referenced_type), TypeOracle::GetSmiTaggedGeneric())) {
      const BitFieldStructType* bitfield_struct =
          BitFieldStructType::DynamicCast(*type_wrapped_in_smi);
      if (bitfield_struct == nullptr) {
        ReportError(
            "When a value of type SmiTagged<T> is used in a field access "
            "expression, T is expected to be a bitfield struct type. Instead, "
            "T "
            "is ",
            **type_wrapped_in_smi);
      }
      const BitField& field = bitfield_struct->LookupField(fieldname);
      return LocationReference::BitFieldAccess(reference, field);
    }
  }
  if (reference.IsHeapReference()) {
    VisitResult ref = reference.heap_reference();
    bool is_const;
    auto generic_type =
        TypeOracle::MatchReferenceGeneric(ref.type(), &is_const);
    if (!generic_type) {
      ReportError(
          "Left-hand side of field access expression is marked as a reference "
          "but is not of type Reference<...>. Found type: ",
          ref.type()->ToString());
    }
    if (auto struct_type = (*generic_type)->StructSupertype()) {
      const Field& field = (*struct_type)->LookupField(fieldname);
      // Update the Reference's type to refer to the field type within the
      // struct.
      ref.SetType(TypeOracle::GetReferenceType(
          field.name_and_type.type,
          is_const ||
              (field.const_qualified && !ignore_stuct_field_constness)));
      if (!field.offset.has_value()) {
        Error("accessing field with unknown offset").Throw();
      }
      if (*field.offset != 0) {
        // Copy the Reference struct up the stack and update the new copy's
        // |offset| value to point to the struct field.
        StackScope scope(this);
        ref = GenerateCopy(ref);
        VisitResult ref_offset = ProjectStructField(ref, "offset");
        VisitResult struct_offset{
            TypeOracle::GetIntPtrType()->ConstexprVersion(),
            std::to_string(*field.offset)};
        VisitResult updated_offset =
            GenerateCall("+", Arguments{{ref_offset, struct_offset}, {}});
        assembler().Poke(ref_offset.stack_range(), updated_offset.stack_range(),
                         ref_offset.type());
        ref = scope.Yield(ref);
      }
      return LocationReference::HeapReference(ref);
    }
  }
  VisitResult object_result = GenerateFetchFromLocation(reference);
  if (std::optional<const ClassType*> class_type =
          object_result.type()->ClassSupertype()) {
    // This is a hack to distinguish the situation where we want to use
    // overloaded field accessors from when we want to create a reference.
    bool has_explicit_overloads = TestLookupCallable(
        QualifiedName{"." + fieldname}, {object_result.type()});
    if ((*class_type)->HasField(fieldname) && !has_explicit_overloads) {
      const Field& field = (*class_type)->LookupField(fieldname);
      if (GlobalContext::collect_language_server_data() && pos.has_value()) {
        LanguageServerData::AddDefinition(*pos, field.pos);
      }
      if (GlobalContext::collect_kythe_data()) {
        KytheData::AddClassFieldUse(*pos, &field);
      }
      return GenerateFieldReference(object_result, field, *class_type);
    }
  }
  return LocationReference::FieldAccess(object_result, fieldname);
}

LocationReference ImplementationVisitor::GetLocationReference(
    ElementAccessExpression* expr) {
  LocationReference reference = GetLocationReference(expr->array);
  VisitResult index = Visit(expr->index);
  if (reference.IsHeapSlice()) {
    return GenerateReferenceToItemInHeapSlice(reference, index);
  } else {
    return LocationReference::ArrayAccess(GenerateFetchFromLocation(reference),
                                          index);
  }
}

LocationReference ImplementationVisitor::GenerateReferenceToItemInHeapSlice(
    LocationReference slice, VisitResult index) {
  DCHECK(slice.IsHeapSlice());
  Arguments arguments{{index}, {}};
  const StructType* slice_type = *slice.heap_slice().type()->StructSupertype();
  Method* method = LookupMethod("AtIndex", slice_type, arguments, {});
  // The reference has to be treated like a normal value when calling methods
  // on the underlying slice implementation.
  LocationReference slice_value =
      LocationReference::Temporary(slice.GetVisitResult(), "slice as value");
  return LocationReference::HeapReference(
      GenerateCall(method, std::move(slice_value), arguments, {}, false));
}

LocationReference ImplementationVisitor::GetLocationReference(
    IdentifierExpression* expr) {
  if (expr->namespace_qualification.empty()) {
    if (std::optional<Binding<LocalValue>*> value =
            TryLookupLocalValue(expr->name->value)) {
      if (GlobalContext::collect_language_server_data()) {
        LanguageServerData::AddDefinition(expr->name->pos,
                                          (*value)->declaration_position());
      }
      if (GlobalContext::collect_kythe_data()) {
        if (!expr->IsThis()) {
          DCHECK_EQ(expr->name->pos.end.column - expr->name->pos.start.column,
                    expr->name->value.length());
          KytheData::AddBindingUse(expr->name->pos, *value);
        }
      }
      if (!expr->generic_arguments.empty()) {
        ReportError("cannot have generic parameters on local name ",
                    expr->name);
      }
      return (*value)->GetLocationReference(*value);
    }
  }

  if (expr->IsThis()) {
    ReportError("\"this\" cannot be qualified");
  }
  QualifiedName name =
      QualifiedName(expr->namespace_qualification, expr->name->value);
  if (std::optional<Builtin*> builtin = Declarations::TryLookupBuiltin(name)) {
    if (GlobalContext::collect_language_server_data()) {
      LanguageServerData::AddDefinition(expr->name->pos,
                                        (*builtin)->Position());
    }
    // TODO(v8:12261): Consider collecting KytheData here.
    return LocationReference::Temporary(GetBuiltinCode(*builtin),
                                        "builtin " + expr->name->value);
  }
  if (!expr->generic_arguments.empty()) {
    GenericCallable* generic = Declarations::LookupUniqueGeneric(name);
    Callable* specialization =
        GetOrCreateSpecialization(SpecializationKey<GenericCallable>{
            generic, TypeVisitor::ComputeTypeVector(expr->generic_arguments)});
    if (Builtin* builtin = Builtin::DynamicCast(specialization)) {
      DCHECK(!builtin->IsExternal());
      return LocationReference::Temporary(GetBuiltinCode(builtin),
                                          "builtin " + expr->name->value);
    } else {
      ReportError("cannot create function pointer for non-builtin ",
                  generic->name());
    }
  }
  Value* value = Declarations::LookupValue(name);
  CHECK(value->Position().source.IsValid());
  if (auto stream = CurrentFileStreams::Get()) {
    stream->required_builtin_includes.insert(value->Position().source);
  }
  if (GlobalContext::collect_language_server_data()) {
    LanguageServerData::AddDefinition(expr->name->pos, value->name()->pos);
  }
  if (auto* constant = NamespaceConstant::DynamicCast(value)) {
    if (GlobalContext::collect_kythe_data()) {
      KytheData::AddConstantUse(expr->name->pos, constant);
    }
    if (constant->type()->IsConstexpr()) {
      return LocationReference::Temporary(
          VisitResult(constant->type(), constant->external_name() + "(state_)"),
          "namespace constant " + expr->name->value);
    }
    assembler().Emit(NamespaceConstantInstruction{constant});
    StackRange stack_range =
        assembler().TopRange(LoweredSlotCount(constant->type()));
    return LocationReference::Temporary(
        VisitResult(constant->type(), stack_range),
        "namespace constant " + expr->name->value);
  }
  ExternConstant* constant = ExternConstant::cast(value);
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddConstantUse(expr->name->pos, constant);
  }
  return LocationReference::Temporary(constant->value(),
                                      "extern value " + expr->name->value);
}

LocationReference ImplementationVisitor::GetLocationReference(
    DereferenceExpression* expr) {
  VisitResult ref = Visit(expr->reference);
  if (!TypeOracle::MatchReferenceGeneric(ref.type())) {
    Error("Operator * expects a reference type but found a value of type ",
          *ref.type())
        .Throw();
  }
  return LocationReference::HeapReference(ref);
}

VisitResult ImplementationVisitor::GenerateFetchFromLocation(
    const LocationReference& reference) {
  if (reference.IsTemporary()) {
    return GenerateCopy(reference.temporary());
  } else if (reference.IsVariableAccess()) {
    return GenerateCopy(reference.variable());
  } else if (reference.IsHeapReference()) {
    const Type* referenced_type = *reference.ReferencedType();
    if (referenced_type == TypeOracle::GetFloat64OrHoleType()) {
      return GenerateCall(QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                                        "LoadFloat64OrHole"),
                          Arguments{{reference.heap_reference()}, {}});
    } else if (auto struct_type = referenced_type->StructSupertype()) {
      StackRange result_range = assembler().TopRange(0);
      for (const Field& field : (*struct_type)->fields()) {
        StackScope scope(this);
        const std::string& fieldname = field.name_and_type.name;
        VisitResult field_value = scope.Yield(GenerateFetchFromLocation(
            GenerateFieldAccess(reference, fieldname)));
        result_range.Extend(field_value.stack_range());
      }
      return VisitResult(referenced_type, result_range);
    } else {
      GenerateCopy(reference.heap_reference());
      FieldSynchronization sync = reference.heap_reference_synchronization();
      assembler().Emit(LoadReferenceInstruction{referenced_type, sync});
      DCHECK_EQ(1, LoweredSlotCount(referenced_type));
      return VisitResult(referenced_type, assembler().TopRange(1));
    }
  } else if (reference.IsBitFieldAccess()) {
    // First fetch the bitfield struct, then get the bits out of it.
    VisitResult bit_field_struct =
        GenerateFetchFromLocation(reference.bit_field_struct_location());
    assembler().Emit(LoadBitFieldInstruction{bit_field_struct.type(),
                                             reference.bit_field()});
    return VisitResult(*reference.ReferencedType(), assembler().TopRange(1));
  } else {
    if (reference.IsHeapSlice()) {
      ReportError(
          "fetching a value directly from an indexed field isn't allowed");
    }
    DCHECK(reference.IsCallAccess());
    return GenerateCall(reference.eval_function(),
                        Arguments{reference.call_arguments(), {}});
  }
}

void ImplementationVisitor::GenerateAssignToLocation(
    const LocationReference& reference, const VisitResult& assignment_value) {
  if (reference.IsCallAccess()) {
    Arguments arguments{reference.call_arguments(), {}};
    arguments.parameters.push_back(assignment_value);
    GenerateCall(reference.assign_function(), arguments);
  } else if (reference.IsVariableAccess()) {
    VisitResult variable = reference.variable();
    VisitResult converted_value =
        GenerateImplicitConvert(variable.type(), assignment_value);
    assembler().Poke(variable.stack_range(), converted_value.stack_range(),
                     variable.type());

    // Local variables are detected by the existence of a binding. Assignment
    // to local variables is recorded to support lint errors.
    if (reference.binding()) {
      (*reference.binding())->SetWritten();
    }
  } else if (reference.IsHeapSlice()) {
    ReportError("assigning a value directly to an indexed field isn't allowed");
  } else if (reference.IsHeapReference()) {
    const Type* referenced_type = *reference.ReferencedType();
    if (reference.IsConst()) {
      Error("cannot assign to const value of type ", *referenced_type).Throw();
    }
    if (referenced_type == TypeOracle::GetFloat64OrHoleType()) {
      GenerateCall(
          QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                        "StoreFloat64OrHole"),
          Arguments{{reference.heap_reference(), assignment_value}, {}});
    } else if (auto struct_type = referenced_type->StructSupertype()) {
      if (!assignment_value.type()->IsSubtypeOf(referenced_type)) {
        ReportError("Cannot assign to ", *referenced_type,
                    " with value of type ", *assignment_value.type());
      }
      for (const Field& field : (*struct_type)->fields()) {
        const std::string& fieldname = field.name_and_type.name;
        // Allow assignment of structs even if they contain const fields.
        // Const on struct fields just disallows direct writes to them.
        bool ignore_stuct_field_constness = true;
        GenerateAssignToLocation(
            GenerateFieldAccess(reference, fieldname,
                                ignore_stuct_field_constness),
            ProjectStructField(assignment_value, fieldname));
      }
    } else {
      GenerateCopy(reference.heap_reference());
      VisitResult converted_assignment_value =
          GenerateImplicitConvert(referenced_type, assignment_value);
      if (referenced_type == TypeOracle::GetFloat64Type()) {
        VisitResult silenced_float_value = GenerateCall(
            "Float64SilenceNaN", Arguments{{assignment_value}, {}});
        assembler().Poke(converted_assignment_value.stack_range(),
                         silenced_float_value.stack_range(), referenced_type);
      }
      assembler().Emit(StoreReferenceInstruction{referenced_type});
    }
  } else if (reference.IsBitFieldAccess()) {
    // First fetch the bitfield struct, then set the updated bits, then store
    // it back to where we found it.
    VisitResult bit_field_struct =
        GenerateFetchFromLocation(reference.bit_field_struct_location());
    VisitResult converted_value =
        GenerateImplicitConvert(*reference.ReferencedType(), assignment_value);
    VisitResult updated_bit_field_struct =
        GenerateSetBitField(bit_field_struct.type(), reference.bit_field(),
                            bit_field_struct, converted_value);
    GenerateAssignToLocation(reference.bit_field_struct_location(),
                             updated_bit_field_struct);
  } else {
    DCHECK(reference.IsTemporary());
    ReportError("cannot assign to const-bound or temporary ",
                reference.temporary_description());
  }
}

VisitResult ImplementationVisitor::GeneratePointerCall(
    Expression* callee, const Arguments& arguments, bool is_tailcall) {
  StackScope scope(this);
  TypeVector parameter_types(arguments.parameters.ComputeTypeVector());
  VisitResult callee_result = Visit(callee);
  if (!callee_result.type()->IsBuiltinPointerType()) {
    std::stringstream stream;
    stream << "Expected a function pointer type but found "
           << *callee_result.type();
    ReportError(stream.str());
  }
  const BuiltinPointerType* type =
      BuiltinPointerType::cast(callee_result.type());

  if (type->parameter_types().size() != parameter_types.size()) {
    std::stringstream stream;
    stream << "parameter count mismatch calling function pointer with Type: "
           << *type << " - expected "
           << std::to_string(type->parameter_types().size()) << ", found "
           << std::to_string(parameter_types.size());
    ReportError(stream.str());
  }

  ParameterTypes types{type->parameter_types(), false};
  Signature sig;
  sig.parameter_types = types;
  if (!IsCompatibleSignature(sig, parameter_types, 0)) {
    std::stringstream stream;
    stream << "parameters do not match function pointer signature. Expected: ("
           << type->parameter_types() << ") but got: (" << parameter_types
           << ")";
    ReportError(stream.str());
  }

  callee_result = GenerateCopy(callee_result);
  StackRange arg_range = assembler().TopRange(0);
  for (size_t current = 0; current < arguments.parameters.size(); ++current) {
    const Type* to_type = type->parameter_types()[current];
    arg_range.Extend(
        GenerateImplicitConvert(to_type, arguments.parameters[current])
            .stack_range());
  }

  assembler().Emit(
      CallBuiltinPointerInstruction{is_tailcall, type, arg_range.Size()});

  if (is_tailcall) {
    return VisitResult::NeverResult();
  }
  DCHECK_EQ(1, LoweredSlotCount(type->return_type()));
  return scope.Yield(VisitResult(type->return_type(), assembler().TopRange(1)));
}

void ImplementationVisitor::AddCallParameter(
    Callable* callable, VisitResult parameter, const Type* parameter_type,
    std::vector<VisitResult>* converted_arguments, StackRange* argument_range,
    std::vector<std::string>* constexpr_arguments, bool inline_macro) {
  VisitResult converted;
  if ((converted_arguments->size() < callable->signature().implicit_count) &&
      parameter.type()->IsTopType()) {
    converted = GenerateCopy(parameter);
  } else {
    converted = GenerateImplicitConvert(parameter_type, parameter);
  }
  converted_arguments->push_back(converted);
  if (!inline_macro) {
    if (converted.IsOnStack()) {
      argument_range->Extend(converted.stack_range());
    } else {
      constexpr_arguments->push_back(converted.constexpr_value());
    }
  }
}

namespace {
std::pair<std::string, std::string> GetClassInstanceTypeRange(
    const ClassType* class_type) {
  std::pair<std::string, std::string> result;
  if (class_type->InstanceTypeRange()) {
    auto instance_type_range = *class_type->InstanceTypeRange();
    std::string instance_type_string_first =
        "static_cast<InstanceType>(" +
        std::to_string(instance_type_range.first) + ")";
    std::string instance_type_string_second =
        "static_cast<InstanceType>(" +
        std::to_string(instance_type_range.second) + ")";
    result =
        std::make_pair(instance_type_string_first, instance_type_string_second);
  } else {
    ReportError(
        "%Min/MaxInstanceType must take a class type that is either a string "
        "or has a generated instance type range");
  }
  return result;
}
}  // namespace

VisitResult ImplementationVisitor::GenerateCall(
    Callable* callable, std::optional<LocationReference> this_reference,
    Arguments arguments, const TypeVector& specialization_types,
    bool is_tailcall) {
  CHECK(callable->Position().source.IsValid());
  if (auto stream = CurrentFileStreams::Get()) {
    stream->required_builtin_includes.insert(callable->Position().source);
  }

  const Type* return_type = callable->signature().return_type;

  if (is_tailcall) {
    if (Builtin* builtin = Builtin::DynamicCast(CurrentCallable::Get())) {
      const Type* outer_return_type = builtin->signature().return_type;
      if (!return_type->IsSubtypeOf(outer_return_type)) {
        Error("Cannot tailcall, type of result is ", *return_type,
              " but should be a subtype of ", *outer_return_type, ".");
      }
    } else {
      Error("Tail calls are only allowed from builtins");
    }
  }

  bool inline_macro = callable->ShouldBeInlined(output_type_);
  std::vector<VisitResult> implicit_arguments;
  for (size_t i = 0; i < callable->signature().implicit_count; ++i) {
    std::string implicit_name = callable->signature().parameter_names[i]->value;
    std::optional<Binding<LocalValue>*> val =
        TryLookupLocalValue(implicit_name);
    if (val) {
      implicit_arguments.push_back(
          GenerateFetchFromLocation((*val)->GetLocationReference(*val)));
    } else {
      VisitResult unititialized = VisitResult::TopTypeResult(
          "implicit parameter '" + implicit_name +
              "' is not defined when invoking " + callable->ReadableName() +
              " at " + PositionAsString(CurrentSourcePosition::Get()),
          callable->signature().parameter_types.types[i]);
      implicit_arguments.push_back(unititialized);
    }
    const Type* type = implicit_arguments.back().type();
    if (const TopType* top_type = TopType::DynamicCast(type)) {
      if (!callable->IsMacro() || callable->IsExternal()) {
        ReportError(
            "unititialized implicit parameters can only be passed to "
            "Torque-defined macros: the ",
            top_type->reason());
      }
      inline_macro = true;
    }
  }

  std::vector<VisitResult> converted_arguments;
  StackRange argument_range = assembler().TopRange(0);
  std::vector<std::string> constexpr_arguments;

  size_t current = 0;
  for (; current < callable->signature().implicit_count; ++current) {
    AddCallParameter(callable, implicit_arguments[current],
                     callable->signature().parameter_types.types[current],
                     &converted_arguments, &argument_range,
                     &constexpr_arguments, inline_macro);
  }

  if (this_reference) {
    DCHECK(callable->IsMethod());
    Method* method = Method::cast(callable);
    // By now, the this reference should either be a variable, a temporary or
    // a Slice. In either case the fetch of the VisitResult should succeed.
    VisitResult this_value = this_reference->GetVisitResult();
    if (inline_macro) {
      if (!this_value.type()->IsSubtypeOf(method->aggregate_type())) {
        ReportError("this parameter must be a subtype of ",
                    *method->aggregate_type(), " but it is of type ",
                    *this_value.type());
      }
    } else {
      AddCallParameter(callable, this_value, method->aggregate_type(),
                       &converted_arguments, &argument_range,
                       &constexpr_arguments, inline_macro);
    }
    ++current;
  }

  for (const auto& arg : arguments.parameters) {
    const Type* to_type = (current >= callable->signature().types().size())
                              ? TypeOracle::GetObjectType()
                              : callable->signature().types()[current++];
    AddCallParameter(callable, arg, to_type, &converted_arguments,
                     &argument_range, &constexpr_arguments, inline_macro);
  }

  size_t label_count = callable->signature().labels.size();
  if (label_count != arguments.labels.size()) {
    std::stringstream s;
    s << "unexpected number of otherwise labels for "
      << callable->ReadableName() << " (expected "
      << std::to_string(label_count) << " found "
      << std::to_string(arguments.labels.size()) << ")";
    ReportError(s.str());
  }

  if (callable->IsTransitioning()) {
    if (!CurrentCallable::Get()->IsTransitioning()) {
      std::stringstream s;
      s << *CurrentCallable::Get()
        << " isn't marked transitioning but calls the transitioning "
        << *callable;
      ReportError(s.str());
    }
  }

  if (auto* builtin = Builtin::DynamicCast(callable)) {
    std::optional<Block*> catch_block = GetCatchBlock();
    assembler().Emit(CallBuiltinInstruction{
        is_tailcall, builtin, argument_range.Size(), catch_block});
    GenerateCatchBlock(catch_block);
    if (is_tailcall) {
      return VisitResult::NeverResult();
    } else if (return_type->IsNever()) {
      assembler().Emit(AbortInstruction{AbortInstruction::Kind::kUnreachable});
      return VisitResult::NeverResult();
    } else {
      size_t slot_count = LoweredSlotCount(return_type);
      if (builtin->IsStub()) {
        if (slot_count < 1 || slot_count > 2) {
          ReportError(
              "Builtin with stub linkage is expected to return one or two "
              "values but returns ",
              slot_count);
        }
      } else {
        if (slot_count != 1) {
          ReportError(
              "Builtin with JS linkage is expected to return one value but "
              "returns ",
              slot_count);
        }
      }
      return VisitResult(return_type, assembler().TopRange(slot_count));
    }
  } else if (auto* macro = Macro::DynamicCast(callable)) {
    if (is_tailcall) {
      ReportError("can't tail call a macro");
    }

    macro->SetUsed();

    // If we're currently generating a C++ macro and it's calling another macro,
    // then we need to make sure that we also generate C++ code for the called
    // macro within the same -inl.inc file.
    if ((output_type_ == OutputType::kCC ||
         output_type_ == OutputType::kCCDebug) &&
        !inline_macro) {
      if (auto* torque_macro = TorqueMacro::DynamicCast(macro)) {
        auto* streams = CurrentFileStreams::Get();
        SourceId file = streams ? streams->file : SourceId::Invalid();
        GlobalContext::EnsureInCCOutputList(torque_macro, file);
      }
    }

    // TODO(torque-builder): Consider a function builder here.
    if (return_type->IsConstexpr()) {
      DCHECK_EQ(0, arguments.labels.size());
      std::stringstream result;
      result << "(";
      bool first = true;
      switch (output_type_) {
        case OutputType::kCSA: {
          if (auto* extern_macro = ExternMacro::DynamicCast(macro)) {
            result << extern_macro->external_assembler_name() << "(state_)."
                   << extern_macro->ExternalName() << "(";
          } else {
            result << macro->ExternalName() << "(state_";
            first = false;
          }
          break;
        }
        case OutputType::kCC: {
          auto* extern_macro = ExternMacro::DynamicCast(macro);
          CHECK_NOT_NULL(extern_macro);
          result << extern_macro->CCName() << "(";
          break;
        }
        case OutputType::kCCDebug: {
          auto* extern_macro = ExternMacro::DynamicCast(macro);
          CHECK_NOT_NULL(extern_macro);
          result << extern_macro->CCDebugName() << "(accessor";
          first = false;
          break;
        }
      }
      for (const VisitResult& arg : converted_arguments) {
        DCHECK(!arg.IsOnStack());
        if (!first) {
          result << ", ";
        }
        first = false;
        result << arg.constexpr_value();
      }
      result << "))";
      return VisitResult(return_type, result.str());
    } else if (inline_macro) {
      std::vector<Block*> label_blocks;
      label_blocks.reserve(arguments.labels.size());
      for (Binding<LocalLabel>* label : arguments.labels) {
        label_blocks.push_back(label->block);
      }
      return InlineMacro(macro, this_reference, converted_arguments,
                         std::move(label_blocks));
    } else if (arguments.labels.empty() &&
               return_type != TypeOracle::GetNeverType()) {
      std::optional<Block*> catch_block = GetCatchBlock();
      assembler().Emit(CallCsaMacroInstruction{
          macro, std::move(constexpr_arguments), catch_block});
      GenerateCatchBlock(catch_block);
      size_t return_slot_count = LoweredSlotCount(return_type);
      return VisitResult(return_type, assembler().TopRange(return_slot_count));
    } else {
      std::optional<Block*> return_continuation;
      if (return_type != TypeOracle::GetNeverType()) {
        return_continuation = assembler().NewBlock();
      }

      std::vector<Block*> label_blocks;

      for (size_t i = 0; i < label_count; ++i) {
        label_blocks.push_back(assembler().NewBlock());
      }
      std::optional<Block*> catch_block = GetCatchBlock();
      assembler().Emit(CallCsaMacroAndBranchInstruction{
          macro, constexpr_arguments, return_continuation, label_blocks,
          catch_block});
      GenerateCatchBlock(catch_block);

      for (size_t i = 0; i < label_count; ++i) {
        Binding<LocalLabel>* label = arguments.labels[i];
        size_t callee_label_parameters =
            callable->signature().labels[i].types.size();
        if (label->parameter_types.size() != callee_label_parameters) {
          std::stringstream s;
          s << "label " << label->name()
            << " doesn't have the right number of parameters (found "
            << std::to_string(label->parameter_types.size()) << " expected "
            << std::to_string(callee_label_parameters) << ")";
          ReportError(s.str());
        }
        assembler().Bind(label_blocks[i]);
        assembler().Goto(
            label->block,
            LowerParameterTypes(callable->signature().labels[i].types).size());

        size_t j = 0;
        for (auto t : callable->signature().labels[i].types) {
          const Type* parameter_type = label->parameter_types[j];
          if (!t->IsSubtypeOf(parameter_type)) {
            ReportError("mismatch of label parameters (label expects ",
                        *parameter_type, " but macro produces ", *t,
                        " for parameter ", i + 1, ")");
          }
          j++;
        }
      }

      if (return_continuation) {
        assembler().Bind(*return_continuation);
        size_t return_slot_count = LoweredSlotCount(return_type);
        return VisitResult(return_type,
                           assembler().TopRange(return_slot_count));
      } else {
        return VisitResult::NeverResult();
      }
    }
  } else if (auto* runtime_function = RuntimeFunction::DynamicCast(callable)) {
    std::optional<Block*> catch_block = GetCatchBlock();
    assembler().Emit(CallRuntimeInstruction{
        is_tailcall, runtime_function, argument_range.Size(), catch_block});
    GenerateCatchBlock(catch_block);
    if (is_tailcall || return_type == TypeOracle::GetNeverType()) {
      return VisitResult::NeverResult();
    } else {
      size_t slot_count = LoweredSlotCount(return_type);
      DCHECK_LE(slot_count, 1);
      // TODO(turbofan): Actually, runtime functions have to return a value, so
      // we should assert slot_count == 1 here.
      return VisitResult(return_type, assembler().TopRange(slot_count));
    }
  } else if (auto* intrinsic = Intrinsic::DynamicCast(callable)) {
    if (intrinsic->ExternalName() == "%SizeOf") {
      if (specialization_types.size() != 1) {
        ReportError("%SizeOf must take a single type parameter");
      }
      const Type* type = specialization_types[0];
      std::string size_string;
      if (std::optional<std::tuple<size_t, std::string>> size = SizeOf(type)) {
        size_string = std::get<1>(*size);
      } else {
        Error("size of ", *type, " is not known.");
      }
      return VisitResult(return_type, size_string);
    } else if (intrinsic->ExternalName() == "%ClassHasMapConstant") {
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%ClassHasMapConstant must take a class type parameter");
      }
      // If the class isn't actually used as the parameter to a TNode,
      // then we can't rely on the class existing in C++ or being of the same
      // type (e.g. it could be a template), so don't use the template CSA
      // machinery for accessing the class' map.
      if (class_type->name() != class_type->GetGeneratedTNodeTypeName()) {
        return VisitResult(return_type, std::string("false"));
      } else {
        return VisitResult(
            return_type,
            std::string("CodeStubAssembler(state_).ClassHasMapConstant<") +
                class_type->name() + ">()");
      }
    } else if (intrinsic->ExternalName() == "%MinInstanceType") {
      if (specialization_types.size() != 1) {
        ReportError("%MinInstanceType must take a single type parameter");
      }
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%MinInstanceType must take a class type parameter");
      }
      std::pair<std::string, std::string> instance_types =
          GetClassInstanceTypeRange(class_type);
      return VisitResult(return_type, instance_types.first);
    } else if (intrinsic->ExternalName() == "%MaxInstanceType") {
      if (specialization_types.size() != 1) {
        ReportError("%MaxInstanceType must take a single type parameter");
      }
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%MaxInstanceType must take a class type parameter");
      }
      std::pair<std::string, std::string> instance_types =
          GetClassInstanceTypeRange(class_type);
      return VisitResult(return_type, instance_types.second);
    } else if (intrinsic->ExternalName() == "%RawConstexprCast") {
      if (intrinsic->signature().parameter_types.types.size() != 1 ||
          constexpr_arguments.size() != 1) {
        ReportError(
            "%RawConstexprCast must take a single parameter with constexpr "
            "type");
      }
      if (!return_type->IsConstexpr()) {
        std::stringstream s;
        s << *return_type
          << " return type for %RawConstexprCast is not constexpr";
        ReportError(s.str());
      }
      std::stringstream result;
      result << "static_cast<" << return_type->GetGeneratedTypeName() << ">(";
      result << constexpr_arguments[0];
      result << ")";
      return VisitResult(return_type, result.str());
    } else if (intrinsic->ExternalName() == "%IndexedFieldLength") {
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("%IndexedFieldLength must take a class type parameter");
      }
      const Field& field =
          class_type->LookupField(StringLiteralUnquote(constexpr_arguments[0]));
      return GenerateArrayLength(VisitResult(type, argument_range), field);
    } else if (intrinsic->ExternalName() == "%MakeLazy") {
      if (specialization_types[0]->IsStructType()) {
        ReportError("%MakeLazy can't use macros that return structs");
      }
      std::string getter_name = StringLiteralUnquote(constexpr_arguments[0]);

      // Normally the parser would split namespace names for us, but we
      // sidestepped it by putting the macro name in a string literal.
      QualifiedName qualified_getter_name = QualifiedName::Parse(getter_name);

      // converted_arguments contains all of the arguments to %MakeLazy. We're
      // looking for a function that takes all but the first.
      Arguments arguments_to_getter;
      arguments_to_getter.parameters.insert(
          arguments_to_getter.parameters.begin(),
          converted_arguments.begin() + 1, converted_arguments.end());

      Callable* callable_macro = LookupCallable(
          qualified_getter_name, Declarations::Lookup(qualified_getter_name),
          arguments_to_getter, {});
      Macro* getter = Macro::DynamicCast(callable_macro);
      if (!getter || getter->IsMethod()) {
        ReportError(
            "%MakeLazy expects a macro, not builtin or other type of callable");
      }
      if (!getter->signature().labels.empty()) {
        ReportError("%MakeLazy requires a macro with no labels");
      }
      if (!getter->signature().return_type->IsSubtypeOf(
              specialization_types[0])) {
        ReportError("%MakeLazy expected return type ", *specialization_types[0],
                    " but found ", *getter->signature().return_type);
      }
      if (getter->signature().implicit_count > 0) {
        ReportError("Implicit parameters are not yet supported in %MakeLazy");
      }

      getter->SetUsed();  // Prevent warnings about unused macros.

      // Now that we've looked up the getter macro, we have to convert the
      // arguments again, so that, for example, constexpr arguments can be
      // coerced to non-constexpr types and put on the stack.

      std::vector<VisitResult> converted_arguments_for_getter;
      StackRange argument_range_for_getter = assembler().TopRange(0);
      std::vector<std::string> constexpr_arguments_for_getter;

      size_t arg_count = 0;
      for (const auto& arg : arguments_to_getter.parameters) {
        DCHECK_LT(arg_count, getter->signature().types().size());
        const Type* to_type = getter->signature().types()[arg_count++];
        AddCallParameter(getter, arg, to_type, &converted_arguments_for_getter,
                         &argument_range_for_getter,
                         &constexpr_arguments_for_getter,
                         /*inline_macro=*/false);
      }

      // Now that the arguments are prepared, emit the instruction that consumes
      // them.
      assembler().Emit(MakeLazyNodeInstruction{
          getter, return_type, std::move(constexpr_arguments_for_getter)});
      return VisitResult(return_type, assembler().TopRange(1));
    } else if (intrinsic->ExternalName() == "%FieldSlice") {
      const Type* type = specialization_types[0];
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (!class_type) {
        ReportError("The first type parameter to %FieldSlice must be a class");
      }
      const Field& field =
          class_type->LookupField(StringLiteralUnquote(constexpr_arguments[0]));
      const Type* expected_slice_type =
          field.const_qualified
              ? TypeOracle::GetConstSliceType(field.name_and_type.type)
              : TypeOracle::GetMutableSliceType(field.name_and_type.type);
      const Type* declared_slice_type = specialization_types[1];
      if (expected_slice_type != declared_slice_type) {
        Error(
            "The second type parameter to %FieldSlice must be the precise "
            "slice type for the named field");
      }
      LocationReference ref = GenerateFieldReference(
          VisitResult(type, argument_range), field, class_type,
          /*treat_optional_as_indexed=*/true);
      if (!ref.IsHeapSlice()) {
        ReportError("%FieldSlice expected an indexed or optional field");
      }
      return ref.heap_slice();
    } else {
      assembler().Emit(CallIntrinsicInstruction{intrinsic, specialization_types,
                                                constexpr_arguments});
      size_t return_slot_count =
          LoweredSlotCount(intrinsic->signature().return_type);
      return VisitResult(return_type, assembler().TopRange(return_slot_count));
    }
  } else {
    UNREACHABLE();
  }
}

VisitResult ImplementationVisitor::GenerateCall(
    const QualifiedName& callable_name, Arguments arguments,
    const TypeVector& specialization_types, bool is_tailcall) {
  Callable* callable =
      LookupCallable(callable_name, Declarations::Lookup(callable_name),
                     arguments, specialization_types);
  return GenerateCall(callable, std::nullopt, arguments, specialization_types,
                      is_tailcall);
}

VisitResult ImplementationVisitor::Visit(CallExpression* expr,
                                         bool is_tailcall) {
  StackScope scope(this);

  if (expr->callee->name->value == "&" && expr->arguments.size() == 1) {
    if (auto* loc_expr = LocationExpression::DynamicCast(expr->arguments[0])) {
      LocationReference ref = GetLocationReference(loc_expr);
      if (ref.IsHeapReference()) return scope.Yield(ref.heap_reference());
      if (ref.IsHeapSlice()
```