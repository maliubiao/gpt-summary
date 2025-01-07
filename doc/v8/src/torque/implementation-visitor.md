Response: The user wants a summary of the functionality of the provided C++ code snippet from the file `v8/src/torque/implementation-visitor.cc`. The request also asks to explain its relationship with JavaScript and provide a JavaScript example if applicable.

**Plan:**

1. **Identify the core class:** The code heavily features the `ImplementationVisitor` class. This likely indicates the primary function.
2. **Analyze the methods:**  Examine the purpose of the member functions of `ImplementationVisitor`. Keywords like "Visit", "Generate", "Inline", and the types of arguments they take will be crucial.
3. **Infer the overall goal:** Based on the method names and the included headers, deduce what `ImplementationVisitor` is designed to do within the Torque compiler. Torque is V8's internal language for specifying built-in functions.
4. **Connect to JavaScript:** Explain how the actions of the `ImplementationVisitor` relate to the execution of JavaScript code in V8. Think about how built-in functions are invoked.
5. **Construct a JavaScript example:** Create a simple JavaScript snippet that would involve the kind of built-in function processing that `ImplementationVisitor` handles.
This C++ code snippet defines the `ImplementationVisitor` class, which is a crucial component in the Torque compiler. Its primary function is to traverse the Abstract Syntax Tree (AST) of Torque code and generate the corresponding C++ or CodeStubAssembler (CSA) code. Essentially, it translates high-level Torque definitions into lower-level V8 implementation details.

Here's a breakdown of its functionalities within this part of the code:

* **File Handling:** It manages the creation and writing to various output files (`.cc` and `.h` for CSA and class definitions). It sets up namespaces and include guards for these files.
* **Namespace Constant Handling:**  It handles the generation of C++ code for namespace constants defined in Torque. This involves creating function declarations in header files and definitions in source files.
* **Macro Inlining:** It implements a mechanism for inlining Torque macros. This involves managing a stack of currently inlining macros to detect and prevent recursive calls. It handles parameter binding, label binding, and return value management during inlining.
* **Macro and Method Generation:** It generates C++ or CSA code for Torque macros and methods. This includes creating function declarations and definitions, handling parameters (including the implicit `this` parameter for methods), and managing local labels for control flow. It supports generating code for different output types (CC, CCDebug, and CSA).
* **Builtin Function Generation:** It handles the generation of C++ CSA code for Torque built-in functions. This involves setting up the function signature, handling implicit parameters (like `context`, `receiver`, `newTarget`), and generating code to call the built-in's implementation. It also supports handling JavaScript builtins with variable or fixed arguments.
* **Variable Declaration Handling:** It processes variable declarations, ensuring proper initialization for constant variables and managing variable bindings within scopes.
* **Control Flow Statement Handling (Partial):** It begins to handle control flow statements like `if` and `goto`. For `if` statements, it distinguishes between compile-time constant expressions (`constexpr`) and runtime conditions. For `goto`, it resolves label references and ensures the correct number of arguments are passed.
* **Expression Handling (Partial):** It starts processing various expressions, including conditional expressions, logical OR/AND expressions, increment/decrement operators, assignment expressions, and literal expressions (floating-point, integer, string).
* **Type Conversion:** It implicitly performs type conversions when necessary, for example, when assigning a value to a variable of a different but compatible type.
* **Error Reporting:** It includes mechanisms for reporting errors during the compilation process, such as incorrect parameter counts or type mismatches.

**Relationship with JavaScript and Example:**

The `ImplementationVisitor` plays a crucial role in how JavaScript code is executed in V8. Torque is used to define the *implementation* of many built-in JavaScript functions and operations. The `ImplementationVisitor` takes these Torque definitions and translates them into the C++ code that V8 actually executes.

For example, consider a simple JavaScript addition operation:

```javascript
let result = 5 + 10;
```

The `+` operator in JavaScript is implemented as a built-in function within V8. This built-in function might be defined in Torque. The `ImplementationVisitor` would process the Torque definition of this addition operator and generate the corresponding C++ code (likely using CSA) that handles the actual addition of the two numbers within V8's internal representation.

While the specific Torque code for the `+` operator is complex, the `ImplementationVisitor`'s work ensures that when the JavaScript engine encounters `5 + 10`, it executes the correct low-level operations defined in the generated C++ code.

In essence, the `ImplementationVisitor` is a bridge between the high-level, declarative nature of Torque and the low-level, imperative implementation of V8, making it possible for V8 to efficiently execute JavaScript code.

Prompt: 
```
这是目录为v8/src/torque/implementation-visitor.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

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

VisitResult ImplementationVisitor::Visit(ConditionalExpression* expr) {
  Block* true_block = assembler().NewBlock(assembler().CurrentStack());
  Block* false_block = assembler().NewBlock(assembler().CurrentStack());
  Block* done_block = assembler().NewBlock();
  Block* true_conversion_block = assembler().NewBlock();
  GenerateExpressionBranch(expr->condition, true_block, false_block);

  VisitResult left;
  VisitResult right;

  {
    // The code for both paths of the conditional need to be generated first
    // before evaluating the conditional expression because the common type of
    // the result of both the true and false of the condition needs to be known
    // to convert both branches to a common type.
    assembler().Bind(true_block);
    StackScope left_scope(this);
    left = Visit(expr->if_true);
    assembler().Goto(true_conversion_block);

    const Type* common_type;
    {
      assembler().Bind(false_block);
      StackScope right_scope(this);
      right = Visit(expr->if_false);
      common_type = GetCommonType(left.type(), right.type());
      right = right_scope.Yield(GenerateImplicitConvert(common_type, right));
      assembler().Goto(done_block);
    }

    assembler().Bind(true_conversion_block);
    left = left_scope.Yield(GenerateImplicitConvert(common_type, left));
    assembler().Goto(done_block);
  }

  assembler().Bind(done_block);
  CHECK_EQ(left, right);
  return left;
}

VisitResult ImplementationVisitor::Visit(LogicalOrExpression* expr) {
  StackScope outer_scope(this);
  VisitResult left_result = Visit(expr->left);

  if (left_result.type()->IsConstexprBool()) {
    VisitResult right_result = Visit(expr->right);
    if (!right_result.type()->IsConstexprBool()) {
      ReportError(
          "expected type constexpr bool on right-hand side of operator "
          "||");
    }
    return VisitResult(TypeOracle::GetConstexprBoolType(),
                       std::string("(") + left_result.constexpr_value() +
                           " || " + right_result.constexpr_value() + ")");
  }

  Block* true_block = assembler().NewBlock();
  Block* false_block = assembler().NewBlock();
  Block* done_block = assembler().NewBlock();

  left_result = GenerateImplicitConvert(TypeOracle::GetBoolType(), left_result);
  GenerateBranch(left_result, true_block, false_block);

  assembler().Bind(true_block);
  VisitResult true_result = GenerateBoolConstant(true);
  assembler().Goto(done_block);

  assembler().Bind(false_block);
  VisitResult false_result;
  {
    StackScope false_block_scope(this);
    false_result = false_block_scope.Yield(
        GenerateImplicitConvert(TypeOracle::GetBoolType(), Visit(expr->right)));
  }
  assembler().Goto(done_block);

  assembler().Bind(done_block);
  DCHECK_EQ(true_result, false_result);
  return outer_scope.Yield(true_result);
}

VisitResult ImplementationVisitor::Visit(LogicalAndExpression* expr) {
  StackScope outer_scope(this);
  VisitResult left_result = Visit(expr->left);

  if (left_result.type()->IsConstexprBool()) {
    VisitResult right_result = Visit(expr->right);
    if (!right_result.type()->IsConstexprBool()) {
      ReportError(
          "expected type constexpr bool on right-hand side of operator "
          "&&");
    }
    return VisitResult(TypeOracle::GetConstexprBoolType(),
                       std::string("(") + left_result.constexpr_value() +
                           " && " + right_result.constexpr_value() + ")");
  }

  Block* true_block = assembler().NewBlock();
  Block* false_block = assembler().NewBlock();
  Block* done_block = assembler().NewBlock();

  left_result = GenerateImplicitConvert(TypeOracle::GetBoolType(), left_result);
  GenerateBranch(left_result, true_block, false_block);

  assembler().Bind(true_block);
  VisitResult true_result;
  {
    StackScope true_block_scope(this);
    VisitResult right_result = Visit(expr->right);
    if (TryGetSourceForBitfieldExpression(expr->left) != nullptr &&
        TryGetSourceForBitfieldExpression(expr->right) != nullptr &&
        TryGetSourceForBitfieldExpression(expr->left)->value ==
            TryGetSourceForBitfieldExpression(expr->right)->value) {
      Lint(
          "Please use & rather than && when checking multiple bitfield "
          "values, to avoid complexity in generated code.");
    }
    true_result = true_block_scope.Yield(
        GenerateImplicitConvert(TypeOracle::GetBoolType(), right_result));
  }
  assembler().Goto(done_block);

  assembler().Bind(false_block);
  VisitResult false_result = GenerateBoolConstant(false);
  assembler().Goto(done_block);

  assembler().Bind(done_block);
  DCHECK_EQ(true_result, false_result);
  return outer_scope.Yield(true_result);
}

VisitResult ImplementationVisitor::Visit(IncrementDecrementExpression* expr) {
  StackScope scope(this);
  LocationReference location_ref = GetLocationReference(expr->location);
  VisitResult current_value = GenerateFetchFromLocation(location_ref);
  VisitResult one = {TypeOracle::GetConstInt31Type(), "1"};
  Arguments args;
  args.parameters = {current_value, one};
  VisitResult assignment_value = GenerateCall(
      expr->op == IncrementDecrementOperator::kIncrement ? "+" : "-", args);
  GenerateAssignToLocation(location_ref, assignment_value);
  return scope.Yield(expr->postfix ? current_value : assignment_value);
}

VisitResult ImplementationVisitor::Visit(AssignmentExpression* expr) {
  StackScope scope(this);
  LocationReference location_ref = GetLocationReference(expr->location);
  VisitResult assignment_value;
  if (expr->op) {
    VisitResult location_value = GenerateFetchFromLocation(location_ref);
    assignment_value = Visit(expr->value);
    Arguments args;
    args.parameters = {location_value, assignment_value};
    assignment_value = GenerateCall(*expr->op, args);
    GenerateAssignToLocation(location_ref, assignment_value);
  } else {
    assignment_value = Visit(expr->value);
    GenerateAssignToLocation(location_ref, assignment_value);
  }
  return scope.Yield(assignment_value);
}

VisitResult ImplementationVisitor::Visit(FloatingPointLiteralExpression* expr) {
  const Type* result_type = TypeOracle::GetConstFloat64Type();
  std::stringstream str;
  str << std::setprecision(std::numeric_limits<double>::digits10 + 1)
      << expr->value;
  return VisitResult{result_type, str.str()};
}

VisitResult ImplementationVisitor::Visit(IntegerLiteralExpression* expr) {
  const Type* result_type = TypeOracle::GetIntegerLiteralType();
  std::stringstream str;
  str << "IntegerLiteral("
      << (expr->value.is_negative() ? "true, 0x" : "false, 0x") << std::hex
      << expr->value.absolute_value() << std::dec << "ull)";
  return VisitResult{result_type, str.str()};
}

VisitResult ImplementationVisitor::Visit(AssumeTypeImpossibleExpression* expr) {
  VisitResult result = Visit(expr->expression);
  const Type* result_type = SubtractType(
      result.type(), TypeVisitor::ComputeType(expr->excluded_type));
  if (result_type->IsNever()) {
    ReportError("unreachable code");
  }
  CHECK_EQ(LowerType(result_type), TypeVector{result_type});
  assembler().Emit(UnsafeCastInstruction{result_type});
  result.SetType(result_type);
  return result;
}

VisitResult ImplementationVisitor::Visit(StringLiteralExpression* expr) {
  return VisitResult{
      TypeOracle::GetConstStringType(),
      "\"" + expr->literal.substr(1, expr->literal.size() - 2) + "\""};
}

VisitResult ImplementationVisitor::GetBuiltinCode(Builtin* builtin) {
  if (builtin->IsExternal() || builtin->kind() != Builtin::kStub) {
    ReportError(
        "creating function pointers is only allowed for internal builtins with "
        "stub linkage");
  }
  const Type* type = TypeOracle::GetBuiltinPointerType(
      builtin->signature().parameter_types.types,
      builtin->signature().return_type);
  assembler().Emit(
      PushBuiltinPointerInstruction{builtin->ExternalName(), type});
  return VisitResult(type, assembler().TopRange(1));
}

VisitResult ImplementationVisitor::Visit(LocationExpression* expr) {
  StackScope scope(this);
  return scope.Yield(GenerateFetchFromLocation(GetLocationReference(expr)));
}

VisitResult ImplementationVisitor::Visit(FieldAccessExpression* expr) {
  StackScope scope(this);
  LocationReference location = GetLocationReference(expr);
  if (location.IsBitFieldAccess()) {
    if (auto* identifier = IdentifierExpression::DynamicCast(expr->object)) {
      bitfield_expressions_[expr] = identifier->name;
    }
  }
  return scope.Yield(GenerateFetchFromLocation(location));
}

const Type* ImplementationVisitor::Visit(GotoStatement* stmt) {
  Binding<LocalLabel>* label = LookupLabel(stmt->label->value);
  size_t parameter_count = label->parameter_types.size();
  if (stmt->arguments.size() != parameter_count) {
    ReportError("goto to label has incorrect number of parameters (expected ",
                parameter_count, " found ", stmt->arguments.size(), ")");
  }

  if (GlobalContext::collect_language_server_data()) {
    LanguageServerData::AddDefinition(stmt->label->pos,
                                      label->declaration_position());
  }
  if (GlobalContext::collect_kythe_data()) {
    KytheData::AddBindingUse(stmt->label->pos, label);
  }

  size_t i = 0;
  StackRange arguments = assembler().TopRange(0);
  for (Expression* e : stmt->arguments) {
    StackScope scope(this);
    VisitResult result = Visit(e);
    const Type* parameter_type = label->parameter_types[i++];
    result = GenerateImplicitConvert(parameter_type, result);
    arguments.Extend(scope.Yield(result).stack_range());
  }

  assembler().Goto(label->block, arguments.Size());
  return TypeOracle::GetNeverType();
}

const Type* ImplementationVisitor::Visit(IfStatement* stmt) {
  bool has_else = stmt->if_false.has_value();

  if (stmt->is_constexpr) {
    VisitResult expression_result = Visit(stmt->condition);

    if (!(expression_result.type() == TypeOracle::GetConstexprBoolType())) {
      std::stringstream stream;
      stream << "expression should return type constexpr bool "
             << "but returns type " << *expression_result.type();
      ReportError(stream.str());
    }

    Block* true_block = assembler().NewBlock();
    Block* false_block = assembler().NewBlock();
    Block* done_block = assembler().NewBlock();

    assembler().Emit(ConstexprBranchInstruction{
        expression_result.constexpr_value(), true_block, false_block});

    assembler().Bind(true_block);
    const Type* left_result = Visit(stmt->if_true);
    if (left_result == TypeOracle::GetVoidType()) {
      assembler().Goto(done_block);
    }

    assembler().Bind(false_block);
    const Type* right_result = TypeOracle::GetVoidType();
    if (has_else) {
      right_result = Visit(*stmt->if_false);
    }
    if (right_result == TypeOracle::GetVoidType()) {
      assembler().Goto(done_block);
    }

    if (left_result->IsNever() != right_result->IsNever()) {
      std::stringstream stream;
      stream << "either both or neither branches in a constexpr if statement "
                "must reach their end at"
             << PositionAsString(stmt->pos);
      ReportError(stream.str());
    }

    if (left_result != TypeOracle::GetNeverType()) {
      assembler().Bind(done_block);
    }
    return left_result;
  } else {
    Block* true_block = assembler().NewBlock(assembler().CurrentStack(),
                                             IsDeferred(stmt->if_true));
    Block* false_block =
        assembler().NewBlock(assembler().CurrentStack(),
                             stmt->if_false && IsDeferred(*stmt->if_false));
    GenerateExpressionBranch(stmt->condition, true_block, false_block);

    Block* done_block;
    bool live = false;
    if (has_else) {
      done_block = assembler().NewBlock();
    } else {
      done_block = false_block;
      live = true;
    }

    assembler().Bind(true_block);
    {
      const Type* result = Visit(stmt->if_true);
      if (result == TypeOracle::GetVoidType()) {
        live = true;
        assembler().Goto(done_block);
      }
    }

    if (has_else) {
      assembler().Bind(false_block);
      const Type* result = Visit(*stmt->if_false);
      if (result == TypeOracle::GetVoidType()) {
        live = true;
        assembler().Goto(done_block);
      }
    }

    if (live) {
      assembler().Bind(done_block);
    }
    return live ? TypeOracle::GetVoidType() : TypeOracle::GetNeverType();
  }
}

const Type* ImplementationVisitor::Visit(WhileStatement* stmt) {
  Block* body_block = assembler().NewBlock(assembler().CurrentStack());
  Block* exit_block = assembler().NewBlock(assembler().CurrentStack());

  Block* header_block = assembler().NewBlock();
  assembler().Goto(header_block);

  assembler().Bind(header_block);
  GenerateExpressionBranch(stmt->condition, body_block, exit_block);

  assembler().Bind(body_block);
  {
    BreakContinueActivator activator{exit_block, header_block};
    const Type* body_result = Visit(stmt->body);
    if (body_result != TypeOracle::GetNeverType()) {
      assembler().Goto(header_block);
    }
  }

  assembler().Bind(exit_block);
  return TypeOracle::GetVoidType();
}

const Type* ImplementationVisitor::Visit(BlockStatement* block) {
  BlockBindings<LocalValue> block_bindings(&ValueBindingsManager::Get());
  const Type* type = TypeOracle::GetVoidType();
  for (Statement* s : block->statements) {
    CurrentSourcePosition::Scope source_position(s->pos);
    if (type->IsNever()) {
      ReportError("statement after non-returning statement");
    }
    if (auto* var_declaration = VarDeclarationStatement::DynamicCast(s)) {
      type = Visit(var_declaration, &block_bindings);
    } else {
      type = Visit(s);
    }
  }
  return type;
}

const Type* ImplementationVisitor::Visit(DebugStatement* stmt) {
  std::string reason;
  const Type* return_type;
  AbortInstruction::Kind kind;
  switch (stmt->kind) {
    case DebugStatement::Kind::kUnreachable:
      // Use the same string as in C++ to simplify fuzzer pattern-matching.
      reason = base::kUnreachableCodeMessage;
      return_type = TypeOracle::GetNeverType();
      kind = AbortInstruction::Kind::kUnreachable;
      break;
    case DebugStatement::Kind::kDebug:
      reason = "debug break";
      return_type = TypeOracle::GetVoidType();
      kind = AbortInstruction::Kind::kDebugBreak;
      break;
  }
#if defined(DEBUG)
  assembler().Emit(PrintErrorInstruction{"halting because of " + reason +
                                         " at " + PositionAsString(stmt->pos)});
#endif
  assembler().Emit(AbortInstruction{kind});
  return return_type;
}

namespace {

std::string FormatAssertSource(const std::string& str) {
  // Replace all whitespace characters with a space character.
  std::string str_no_newlines = str;
  std::replace_if(
      str_no_newlines.begin(), str_no_newlines.end(),
      [](unsigned char c) { return isspace(c); }, ' ');

  // str might include indentation, squash multiple space characters into one.
  std::string result;
  std::unique_copy(str_no_newlines.begin(), str_no_newlines.end(),
                   std::back_inserter(result),
                   [](char a, char b) { return a == ' ' && b == ' '; });
  return result;
}

}  // namespace

const Type* ImplementationVisitor::Visit(AssertStatement* stmt) {
  if (stmt->kind == AssertStatement::AssertKind::kStaticAssert) {
    std::string message =
        "static_assert(" + stmt->source + ") at " + ToString(stmt->pos);
    GenerateCall(QualifiedName({"", TORQUE_INTERNAL_NAMESPACE_STRING},
                               STATIC_ASSERT_MACRO_STRING),
                 Arguments{{Visit(stmt->expression),
                            VisitResult(TypeOracle::GetConstexprStringType(),
                                        StringLiteralQuote(message))},
                           {}});
    return TypeOracle::GetVoidType();
  }
  // When the sandbox is off, sbxchecks become dchecks.
  DCHECK_IMPLIES(stmt->kind == AssertStatement::AssertKind::kSbxCheck,
                 V8_ENABLE_SANDBOX_BOOL);
  bool do_check = stmt->kind != AssertStatement::AssertKind::kDcheck ||
                  GlobalContext::force_assert_statements();
#if defined(DEBUG)
  do_check = true;
#endif
  Block* resume_block;

  if (!do_check) {
    Block* unreachable_block = assembler().NewBlock(assembler().CurrentStack());
    resume_block = assembler().NewBlock(assembler().CurrentStack());
    assembler().Goto(resume_block);
    assembler().Bind(unreachable_block);
  }

  // CSA_DCHECK & co. are not used here on purpose for two reasons. First,
  // Torque allows and handles two types of expressions in the if protocol
  // automagically, ones that return TNode<BoolT> and those that use the
  // BranchIf(..., Label* true, Label* false) idiom. Because the machinery to
  // handle this is embedded in the expression handling and to it's not
  // possible to make the decision to use CSA_DCHECK or CSA_DCHECK_BRANCH
  // isn't trivial up-front. Secondly, on failure, the assert text should be
  // the corresponding Torque code, not the -gen.cc code, which would be the
  // case when using CSA_DCHECK_XXX.
  Block* true_block = assembler().NewBlock(assembler().CurrentStack());
  Block* false_block = assembler().NewBlock(assembler().CurrentStack(), true);
  GenerateExpressionBranch(stmt->expression, true_block, false_block);

  assembler().Bind(false_block);

  assembler().Emit(AbortInstruction{
      AbortInstruction::Kind::kAssertionFailure,
      "Torque assert '" + FormatAssertSource(stmt->source) + "' failed"});

  assembler().Bind(true_block);

  if (!do_check) {
    assembler().Bind(resume_block);
  }

  return TypeOracle::GetVoidType();
}

const Type* ImplementationVisitor::Visit(ExpressionStatement* stmt) {
  const Type* type = Visit(stmt->expression).type();
  return type->IsNever() ? type : TypeOracle::GetVoidType();
}

const Type* ImplementationVisitor::Visit(ReturnStatement* stmt) {
  Callable* current_callable = CurrentCallable::Get();
  if (current_callable->signature().return_type->IsNever()) {
    std::stringstream s;
    s << "cannot return from a function with return type never";
    ReportError(s.str());
  }
  LocalLabel* end =
      current_callable->IsMacro() ? LookupLabel(kMacroEndLabelName) : nullptr;
  if (current_callable->HasReturnValue()) {
    if (!stmt->value) {
      std::stringstream s;
      s << "return expression needs to be specified for a return type of "
        << *current_callable->signature().return_type;
      ReportError(s.str());
    }
    VisitResult expression_result = Visit(*stmt->value);
    VisitResult return_result = GenerateImplicitConvert(
        current_callable->signature().return_type, expression_result);
    if (current_callable->IsMacro()) {
      if (return_result.IsOnStack()) {
        StackRange return_value_range =
            GenerateLabelGoto(end, return_result.stack_range());
        SetReturnValue(VisitResult(return_result.type(), return_value_range));
      } else {
        GenerateLabelGoto(end);
        SetReturnValue(return_result);
      }
    } else if (current_callable->IsBuiltin()) {
      assembler().Emit(ReturnInstruction{
          LoweredSlotCount(current_callable->signature().return_type)});
    } else {
      UNREACHABLE();
    }
  } else {
    if (stmt->value) {
      std::stringstream s;
      s << "return expression can't be specified for a void or never return "
           "type";
      ReportError(s.str());
    }
    GenerateLabelGoto(end);
  }
  current_callable->IncrementReturns();
  return TypeOracle::GetNeverType();
}

VisitResult ImplementationVisitor::Visit(TryLabelExpression* expr) {
  size_t parameter_count = expr->label_block->parameters.names.size();
  std::vector<VisitResult> parameters;

  Block* label_block = nullptr;
  Block* done_block = assembler().NewBlock();
  VisitResult try_result;

  {
    CurrentSourcePosition::Scope source_position(expr->label_block->pos);
    if (expr->label_block->parameters.has_varargs) {
      ReportError("cannot use ... for label parameters");
    }
    Stack<const Type*> label_input_stack = assembler().CurrentStack();
    TypeVector parameter_types;
    for (size_t i = 0; i < parameter_count; ++i) {
      const Type* type =
          TypeVisitor::ComputeType(expr->label_block->parameters.types[i]);
      parameter_types.push_back(type);
      if (type->IsConstexpr()) {
        ReportError("no constexpr type allowed for label arguments");
      }
      StackRange range = label_input_stack.PushMany(LowerType(type));
      parameters.push_back(VisitResult(type, range));
    }
    label_block = assembler().NewBlock(label_input_stack,
                                       IsDeferred(expr->label_block->body));

    Binding<LocalLabel> label_binding{
        &LabelBindingsManager::Get(), expr->label_block->label,
        LocalLabel{label_block, std::move(parameter_types)}};

    // Visit try
    StackScope stack_scope(this);
    try_result = Visit(expr->try_expression);
    if (try_result.type() != TypeOracle::GetNeverType()) {
      try_result = stack_scope.Yield(try_result);
      assembler().Goto(done_block);
    }
  }

  // Visit and output the code for the label block. If the label block falls
  // through, then the try must not return a value. Also, if the try doesn't
  // fall through, but the label does, then overall the try-label block
  // returns type void.
  assembler().Bind(label_block);
  const Type* label_result;
  {
    BlockBindings<LocalValue> parameter_bindings(&ValueBindingsManager::Get());
    for (size_t i = 0; i < parameter_count; ++i) {
      Identifier* name = expr->label_block->parameters.names[i];
      parameter_bindings.Add(name,
                             LocalValue{LocationReference::Temporary(
                                 parameters[i], "parameter " + name->value)});
    }

    label_result = Visit(expr->label_block->body);
  }
  if (!try_result.type()->IsVoidOrNever() && label_result->IsVoid()) {
    ReportError(
        "otherwise clauses cannot fall through in a non-void expression");
  }
  if (label_result != TypeOracle::GetNeverType()) {
    assembler().Goto(done_block);
  }
  if (label_result->IsVoid() && try_result.type()->IsNever()) {
    try_result =
        VisitResult(TypeOracle::GetVoidType(), try_result.stack_range());
  }

  if (!try_result.type()->IsNever()) {
    assembler().Bind(done_block);
  }
  return try_result;
}

VisitResult ImplementationVisitor::Visit(StatementExpression* expr) {
  return VisitResult{Visit(expr->statement), assembler().TopRange(0)};
}

InitializerResults ImplementationVisitor::VisitInitializerResults(
    const ClassType* class_type,
    const std::vector<NameAndExpression>& initializers) {
  InitializerResults result;
  for (const NameAndExpression& initializer : initializers) {
    result.names.push_back(initializer.name);
    Expression* e = initializer.expression;
    const Field& field = class_type->LookupField(initializer.name->value);
    bool has_index = field.index.has_value();
    if (SpreadExpression* s = SpreadExpression::DynamicCast(e)) {
      if (!has_index) {
        ReportError(
            "spread expressions can only be used to initialize indexed class "
            "fields ('",
            initializer.name->value, "' is not)");
      }
      e = s->spreadee;
    } else if (has_index) {
      ReportError("the indexed class field '", initializer.name->value,
                  "' must be initialized with a spread operator");
    }
    result.field_value_map[field.name_and_type.name] = Visit(e);
  }
  return result;
}

LocationReference ImplementationVisitor::GenerateFieldReference(
    VisitResult object, const Field& field, const ClassType* class_type,
    bool treat_optional_as_indexed) {
  if (field.index.has_value()) {
    LocationReference slice = LocationReference::HeapSlice(
        GenerateCall(class_type->GetSliceMacroName(field), {{object}, {}}));
    if (field.index->optional && !treat_optional_as_indexed) {
      // This field was declared using optional syntax, so any reference to it
      // is implicitly a reference to the first item.
      return GenerateReferenceToItemInHeapSlice(
          slice, {TypeOracle::GetConstInt31Type(), "0"});
    } else {
      return slice;
    }
  }
  DCHECK(field.offset.has_value());
  StackRange result_range = assembler().TopRange(0);
  result_range.Extend(GenerateCopy(object).stack_range());
  VisitResult offset =
      VisitResult(TypeOracle::GetConstInt31Type(), ToString(*field.offset));
  offset = GenerateImplicitConvert(TypeOracle::GetIntPtrType(), offset);
  result_range.Extend(offset.stack_range());
  const Type* type = TypeOracle::GetReferenceType(field.name_and_type.type,
                                                  field.const_qualified);
  return LocationReference::HeapReference(VisitResult(type, result_range),
                                          field.synchronization);
}

// This is used to generate field references during initialization, where we can
// re-use the offsets used for computing the allocation size.
LocationReference ImplementationVisitor::GenerateFieldReferenceForInit(
    VisitResult object, const Field& field,
    const LayoutForInitialization& layout) {
  StackRange result_range = assembler().TopRange(0);
  result_range.Extend(GenerateCopy(object).stack_range());
  VisitResult offset = GenerateImplicitConvert(
      TypeOracle::GetIntPtrType(), layout.offsets.at(field.name_and_type.name));
  result_range.Extend(offset.stack_range());
  if (field.index) {
    VisitResult length =
        GenerateCopy(layout.array_lengths.at(field.name_and_type.name));
    result_range.Extend(length.stack_range());
    const Type* slice_type =
        TypeOracle::GetMutableSliceType(field.name_and_type.type);
    return LocationReference::HeapSlice(VisitResult(slice_type, result_range));
  } else {
    // Const fields are writable during initialization.
    VisitResult heap_reference(
        TypeOracle::GetMutableReferenceType(field.name_and_type.type),
        result_range);
    return LocationReference::HeapReference(heap_reference);
  }
}

void ImplementationVisitor::InitializeClass(
    const ClassType* class_type, VisitResult allocate_result,
    const InitializerResults& initializer_results,
    const LayoutForInitialization& layout) {
  if (const ClassType* super = class_type->GetSuperClass()) {
    InitializeClass(super, allocate_result, initializer_results, layout);
  }

  for (const Field& f : class_type->fields()) {
    // Support optional padding fields.
    if (f.name_and_type.type->IsVoid()) continue;
    VisitResult initializer_value =
        initializer_results.field_value_map.at(f.name_and_type.name);
    LocationReference field =
        GenerateFieldReferenceForInit(allocate_result, f, layout);
    if (f.index) {
      DCHECK(field.IsHeapSlice());
      VisitResult slice = field.GetVisitResult();
      GenerateCall(QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                                 "InitializeFieldsFromIterator"),
                   {{slice, initializer_value}, {}});
    } else {
      GenerateAssignToLocation(field, initializer_value);
    }
  }
}

VisitResult ImplementationVisitor::GenerateArrayLength(
    Expression* array_length, Namespace* nspace,
    const std::map<std::string, LocalValue>& bindings) {
  StackScope stack_scope(this);
  CurrentSourcePosition::Scope pos_scope(array_length->pos);
  // Switch to the namespace where the class was declared.
  CurrentScope::Scope current_scope_scope(nspace);
  // Reset local bindings and install local binding for the preceding fields.
  BindingsManagersScope bindings_managers_scope;
  BlockBindings<LocalValue> field_bindings(&ValueBindingsManager::Get());
  for (auto& p : bindings) {
    field_bindings.Add(p.first, LocalValue{p.second}, true);
  }
  VisitResult length = Visit(array_length);
  VisitResult converted_length =
      GenerateCall("Convert", Arguments{{length}, {}},
                   {TypeOracle::GetIntPtrType(), length.type()}, false);
  return stack_scope.Yield(converted_length);
}

VisitResult ImplementationVisitor::GenerateArrayLength(VisitResult object,
                                                       const Field& field) {
  DCHECK(field.index);

  StackScope stack_scope(this);
  const ClassType* class_type = *object.type()->ClassSupertype();
  std::map<std::string, LocalValue> bindings;
  bool before_current = true;
  for (const Field& f : class_type->ComputeAllFields()) {
    if (field.name_and_type.name == f.name_and_type.name) {
      before_current = false;
    }
    // We can't generate field references eagerly here, because some preceding
    // fields might be optional, and attempting to get a reference to an
    // optional field can crash the program if the field isn't present.
    // Instead, we use the lazy form of LocalValue to only generate field
    // references if they are used in the length expression.
    bindings.insert(
        {f.name_and_type.name,
         f.const_qualified
             ? (before_current
                    ? LocalValue{[this, object, f, class_type]() {
                        return GenerateFieldReference(object, f, class_type);
                      }}
                    : LocalValue("Array lengths may only refer to fields "
                                 "defined earlier"))
             : LocalValue(
                   "Non-const fields cannot be used for array lengths.")});
  }
  return stack_scope.Yield(
      GenerateArrayLength(field.index->expr, class_type->nspace(), bindings));
}

VisitResult ImplementationVisitor::GenerateArrayLength(
    const ClassType* class_type, const InitializerResults& initializer_results,
    const Field& field) {
  DCHECK(field.index);

  StackScope stack_scope(this);
  std::map<std::string, LocalValue> bindings;
  for (const Field& f : class_type->ComputeAllFields()) {
    if (f.index) break;
    const std::string& fieldname = f.name_and_type.name;
    VisitResult value = initializer_results.field_value_map.at(fieldname);
    bindings.insert(
        {fieldname,
         f.const_qualified
             ? LocalValue{LocationReference::Temporary(
                   value, "initial field " + fieldname)}
             : LocalValue(
                   "Non-const fields cannot be used for array lengths.")});
  }
  return stack_scope.Yield(
      GenerateArrayLength(field.index->expr, class_type->nspace(), bindings));
}

LayoutForInitialization ImplementationVisitor::GenerateLayoutForInitialization(
    const ClassType* class_type,
    const InitializerResults& initializer_results) {
  LayoutForInitialization layout;
  VisitResult offset;
  for (Field f : class_type->ComputeAllFields()) {
    if (f.offset.has_value()) {
      offset =
          VisitResult(TypeOracle::GetConstInt31Type(), ToString(*f.offset));
    }
    layout.offsets[f.name_and_type.name] = offset;
    if (f.index) {
      size_t element_size;
      std::string element_size_string;
      std::tie(element_size, element_size_string) =
          *SizeOf(f.name_and_type.type);
      VisitResult array_element_size =
          VisitResult(TypeOracle::GetConstInt31Type(), element_size_string);
      VisitResult array_length =
          GenerateArrayLength(class_type, initializer_results, f);
      layout.array_lengths[f.name_and_type.name] = array_length;
      Arguments arguments;
      arguments.parameters = {offset, array_length, array_element_size};
      offset = GenerateCall(QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING},
                                          "AddIndexedFieldSizeToObjectSize"),
                            arguments);
    } else {
      DCHECK(f.offset.has_value());
    }
  }
  if (class_type->size().SingleValue()) {
    layout.size = VisitResult(TypeOracle::GetConstInt31Type(),
                              ToString(*class_type->size().SingleValue()));
  } else {
    layout.size = offset;
  }
  if ((size_t{1} << class_type->size().AlignmentLog2()) <
      TargetArchitecture::TaggedSize()) {
    Arguments arguments;
    arguments.parameters = {layout.size};
    layout.size = GenerateCall(
        QualifiedName({TORQUE_INTERNAL_NAMESPACE_STRING}, "AlignTagged"),
        arguments);
  }
  return layout;
}

VisitResult ImplementationVisitor::Visit(NewExpression* expr) {
  StackScope stack_scope(this);
  const Type* type = TypeVisitor::ComputeType(expr->type);
  const ClassType* class_type = ClassType::DynamicCast(type);
  if (class_type == nullptr) {
    ReportError("type for new expression must be a class, \"", *type,
                "\" is not");
  }

  if (!class_type->AllowInstantiation()) {
    // Classes that are only used for testing should never be instantiated.
    ReportError(*c
"""


```