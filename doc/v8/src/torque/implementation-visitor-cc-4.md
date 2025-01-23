Response:
My thinking process to address the user's request involves these steps:

1. **Understanding the Core Request:** The user wants to understand the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's Torque compiler. They've specifically identified the file `v8/src/torque/implementation-visitor.cc`. They also provide context about `.tq` files and the relationship to JavaScript.

2. **Identifying Key Information in the Code:** I scanned the code for recurring patterns, class names, method names, and important variables. Key elements that stood out were:
    * `ImplementationVisitor`: This is the central class. The name suggests it *visits* code and performs some *implementation*-related tasks.
    * `Visit(...)` methods:  These are numerous and take different AST node types as arguments (e.g., `CallExpression`, `CallMethodExpression`, `IntrinsicCallExpression`). This confirms the visitor pattern.
    * `GenerateCall(...)`, `GeneratePointerCall(...)`: These methods suggest the generation of code or instructions.
    * `Arguments`, `TypeVector`: These data structures likely represent function call arguments and type information.
    * `LookupCallable(...)`, `LookupMethod(...)`: These suggest resolving function or method calls.
    * `GenerateImplicitConvert(...)`:  This points to type conversion logic.
    * `GenerateBranch(...)`, `GenerateBoolConstant(...)`, `GenerateExpressionBranch(...)`, `GenerateLabelGoto(...)`: These relate to control flow and basic value generation.
    * `LabelsFromIdentifiers(...)`: This suggests handling labels for jumps and control flow.
    * `LowerParameter(...)`, `LowerLabelParameter(...)`:  These seem to be related to transforming parameters for lower-level code generation.
    * `GenerateBuiltinDefinitionsAndInterfaceDescriptors(...)`, `GenerateVisitorLists(...)`, `GenerateBitFields(...)`: These methods suggest generating metadata or definitions for different aspects of V8.
    * `FieldOffsetsGenerator`, `ClassFieldOffsetGenerator`, `CppClassGenerator`: These relate to generating information about object layouts and class structures.
    * Use of `assembler()`: This strongly indicates interaction with a code generation component.

3. **Inferring High-Level Functionality:** Based on the identified elements, I concluded that `ImplementationVisitor` plays a crucial role in the *code generation* phase of the Torque compiler. It traverses the Abstract Syntax Tree (AST) of the Torque code and translates it into lower-level representations (likely machine code or intermediate representations).

4. **Connecting to Torque and JavaScript:** I remembered that Torque is V8's domain-specific language for writing performance-critical JavaScript built-ins. Therefore, `implementation-visitor.cc` is responsible for taking the high-level `.tq` code and generating the C++ (and potentially assembly) code that implements the corresponding JavaScript functionality.

5. **Formulating a Concise Summary:** I started drafting a high-level summary that captures the essence of the file's purpose. I focused on keywords like "traverses," "generates code," "lower-level representations," and "implements."

6. **Addressing Specific User Questions:**  I went through each of the user's specific requests:
    * **Function Listing:** I listed the key functionalities identified in step 2, grouping them logically.
    * **`.tq` File Explanation:** I confirmed that `.tq` files are Torque source code.
    * **Relationship to JavaScript (with example):** I chose a simple example of a Torque function that could be implemented in JavaScript to illustrate the connection. The example focused on a basic arithmetic operation.
    * **Code Logic Inference (with example):** I selected the `Visit(CallExpression*)` method as it demonstrates call resolution and code generation. I created a simple hypothetical input and described the likely output – a function call in the generated code.
    * **Common Programming Errors:** I considered common errors in programming languages and adapted them to the Torque/V8 context. I focused on type mismatches during function calls as a relevant example.
    * **Overall Function (Part 5 of 7):** I reiterated the core function and placed it within the larger context of the compilation pipeline, emphasizing its role in code generation.

7. **Refining the Language and Structure:**  I ensured the language was clear, concise, and avoided overly technical jargon where possible. I organized the information logically, following the user's request structure. I paid attention to the numbering of the parts (Part 5 of 7).

8. **Self-Correction/Review:** I reread my response to ensure accuracy and completeness. I checked if I had addressed all the user's specific points and if the examples were relevant and easy to understand. For example, I made sure the JavaScript example corresponded to a plausible Torque function. I also ensured that the assumed input and output for the code logic inference were consistent.
好的，这是对 `v8/src/torque/implementation-visitor.cc` 文件功能的归纳：

**v8/src/torque/implementation-visitor.cc 的功能：**

这个文件是 V8 的 Torque 编译器中的一个核心组件，主要负责将 Torque 语言编写的程序实现（例如宏、内置函数、方法等）转换成 V8 运行时可以理解和执行的底层代码，通常是 C++ 代码或汇编代码。`ImplementationVisitor` 类使用访问者模式遍历 Torque 抽象语法树 (AST)，并针对不同的语法结构执行相应的代码生成逻辑。

**具体功能点包括：**

1. **表达式求值与代码生成：**  遍历各种表达式（例如函数调用、方法调用、字面量、变量等），生成相应的 C++ 代码或调用底层的代码生成器 (`assembler()`)。
2. **函数和方法调用处理：**  解析函数和方法的调用，包括查找可调用对象、处理参数、类型特化等，并生成相应的调用代码。
3. **内置函数和内联函数的处理：**  专门处理 Torque 内置函数 (`IntrinsicCallExpression`)，生成相应的调用代码。
4. **控制流生成：**  处理条件语句 (`GenerateBranch`)、布尔常量 (`GenerateBoolConstant`)、标签跳转 (`GenerateLabelGoto`) 等，生成相应的控制流代码。
5. **类型转换：**  处理隐式类型转换 (`GenerateImplicitConvert`)，确保类型安全。
6. **标签管理：**  管理和解析代码中的标签 (`LabelsFromIdentifiers`)，用于实现跳转等控制流。
7. **参数处理：**  处理函数和方法的参数，包括展开结构体参数 (`LowerParameter`, `LowerLabelParameter`)。
8. **外部名称生成：**  生成用于 C++ 代码的外部标签和参数名称 (`ExternalLabelName`, `ExternalLabelParameterName`, `ExternalParameterName`)。
9. **错误处理：**  在遇到无法处理的情况或类型错误时报告错误 (`ReportError`)。
10. **元数据生成：**  生成内置函数的定义 (`GenerateBuiltinDefinitionsAndInterfaceDescriptors`)、访问者列表 (`GenerateVisitorLists`)、位域定义 (`GenerateBitFields`) 等元数据，供 V8 运行时使用。
11. **类和结构体布局生成：**  生成 C++ 中类和结构体的字段偏移量信息 (`ClassFieldOffsetGenerator`)，用于高效地访问对象成员。
12. **遍历所有声明：**  `VisitAllDeclarables` 函数负责遍历所有已声明的 Torque 元素，并触发相应的代码生成。
13. **C++ 代码生成：**  对于需要生成 C++ 代码的宏 (`OutputType::kCC`, `OutputType::kCCDebug`)，也会进行处理。

**如果 v8/src/torque/implementation-visitor.cc 以 .tq 结尾：**

如果文件名以 `.tq` 结尾，那么它本身就是一个 **Torque 源代码文件**，而不是 C++ 源文件。 Torque 文件描述了 V8 运行时需要实现的函数、宏、类型等。  `implementation-visitor.cc` 的作用正是去 *处理* 这些 `.tq` 文件定义的内容。

**与 JavaScript 的关系及示例：**

Torque 的主要目的是编写高性能的 JavaScript 内置函数和运行时功能。 `implementation-visitor.cc` 生成的代码最终会被编译到 V8 引擎中，直接支持 JavaScript 的执行。

例如，假设在某个 `.tq` 文件中定义了一个名为 `StringAdd` 的 Torque 函数，用于实现字符串拼接：

```torque
// hypothetical StringAdd.tq
macro StringAdd(implicit context: Context)(left: String, right: String): String {
  return CallRuntime(Runtime::kStringAdd, context, left, right)
    otherwise (unreachable);
}
```

`implementation-visitor.cc` 在处理这个 `StringAdd` 宏时，会生成类似于下面的 C++ 代码（简化示例）：

```c++
// 生成的 C++ 代码片段 (简化)
TNode<String> TorqueGeneratedTNodeFactory::StringAdd(TNode<Context> p_context, TNode<String> p_left, TNode<String> p_right) {
  // ... 其他代码 ...
  TNode<String> result;
  compiler::TNode<Object> tmp_0;
  tmp_0 = CallRuntime(Runtime::kStringAdd, p_context, p_left, p_right);
  compiler::TNode<String> tmp_1;
  USE(tmp_1);
  compiler::CodeAssemblerLabel label_Otherwise_0_impl(this);
  compiler::GotoIf(IsTheHole(implicit_cast<compiler::TNode<Object>>(tmp_0)), &label_Otherwise_0_impl);
  result = UncheckedCast<String>(tmp_0);
  return result;

  BIND(&label_Otherwise_0_impl);
  Unreachable();
}
```

当 JavaScript 代码执行字符串拼接操作时，V8 可能会调用到这个生成的 `StringAdd` 函数。

**JavaScript 示例：**

```javascript
let str1 = "hello";
let str2 = " world";
let result = str1 + str2; // 这个操作的底层可能由 Torque 定义的 StringAdd 实现
console.log(result); // 输出 "hello world"
```

**代码逻辑推理：假设输入与输出**

考虑 `Visit(CallExpression* expr)` 函数，它处理函数调用表达式。

**假设输入：**  一个 `CallExpression` 对象 `expr`，表示调用一个名为 `Allocate` 的函数，该函数接收一个表示大小的参数。

```c++
// 假设的 CallExpression 结构（简化）
struct CallExpression {
  Identifier* callee; // 指向 "Allocate" 的标识符
  std::vector<Expression*> arguments; // 包含一个表达式，例如表示大小的 IntegerLiteral
  // ... 其他成员 ...
};

// 假设的输入
Identifier* allocate_identifier = new Identifier{"Allocate"};
IntegerLiteral* size_literal = new IntegerLiteral{"10"};
CallExpression* call_expr = new CallExpression{allocate_identifier, {size_literal}};
```

**预期输出：** `Visit` 函数会生成调用底层分配内存的 C++ 代码。假设 `Allocate` 函数在 Torque 中被定义为调用 V8 的堆分配器。生成的代码可能类似于：

```c++
// 生成的 C++ 代码片段 (简化)
TNode<RawPtrT> result;
result = Allocate(isolate_root(), size_value); // size_value 是从 size_literal 求值得到的
```

这里的 `Allocate` 是一个 V8 内部的分配函数，`size_value` 是对 `size_literal` 求值的结果。

**用户常见的编程错误：**

用户在编写 Torque 代码时，常见的编程错误包括：

1. **类型不匹配：**  传递给函数的参数类型与函数签名定义的类型不符。 `implementation-visitor.cc` 中的类型检查和转换逻辑会尝试捕获这类错误。

   **Torque 示例：**

   ```torque
   macro PrintNumber(n: Number): void {
     Print(ToString(n));
   }

   // 错误：传递了字符串而不是 Number
   PrintNumber("hello");
   ```

   `implementation-visitor.cc` 在处理 `PrintNumber("hello")` 时，会发现 `"hello"` 的类型是 `String` 而不是 `Number`，并报告类型错误。

2. **调用不存在的函数或方法：**  尝试调用在当前作用域内未定义的函数或方法。

   **Torque 示例：**

   ```torque
   // 错误：UndefinedFunction 未定义
   UndefinedFunction();
   ```

   `implementation-visitor.cc` 中的查找逻辑 (`LookupCallable`) 会找不到 `UndefinedFunction` 的定义，从而报告错误。

3. **标签使用错误：**  在 `goto` 或 `otherwise` 等控制流语句中使用了不存在的标签。

   **Torque 示例：**

   ```torque
   macro MyMacro(): void {
     goto NonExistentLabel;
     label ExistentLabel:
       Print("Reached here");
   }
   ```

   `implementation-visitor.cc` 在处理 `goto NonExistentLabel` 时，会查找名为 `NonExistentLabel` 的标签，如果找不到则会报告错误。

**归纳一下它的功能 (作为第 5 部分)：**

作为编译过程的第 5 部分（假设前面的部分包括词法分析、语法分析、类型检查等），`v8/src/torque/implementation-visitor.cc` 的主要功能是 **代码生成**。它接收经过语法分析和类型检查的 Torque 抽象语法树，并将其转换成 V8 运行时可以执行的底层代码（通常是 C++ 代码）。这个阶段是连接高级 Torque 语言描述和最终机器执行的关键步骤。它确保了 Torque 代码能够被高效地翻译成 V8 引擎能够理解的形式，从而实现高性能的 JavaScript 内置功能。

### 提示词
```
这是目录为v8/src/torque/implementation-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/implementation-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  CppClassGenerator(const ClassType* type, st
```