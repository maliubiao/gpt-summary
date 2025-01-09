Response:
The user wants a summary of the functionality of the `v8/src/torque/implementation-visitor.cc` file, based on the provided code snippet.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The code snippet starts with `class ImplementationVisitor`. This is the central entity, and its methods define the file's functionality.

2. **Infer Purpose from Class Name:** The name "ImplementationVisitor" suggests that this class is responsible for visiting and processing some abstract syntax tree (AST) to generate an "implementation."  Given the context of "torque," this likely means generating C++ code for V8.

3. **Analyze Key Methods:** Examine the provided methods and their arguments to understand what actions the visitor performs. Look for patterns and recurring themes.

    * **`Visit(NewExpression* expr)`:** Deals with creating new objects. It handles allocation, initialization, and type checking. It seems to generate calls to internal allocation functions.
    * **`Visit(BreakStatement* stmt)` and `Visit(ContinueStatement* stmt)`:** Handle control flow within loops. They generate `goto` statements to specific labels.
    * **`Visit(ForLoopStatement* stmt)`:**  Processes for loops, setting up blocks for the header, body, and exit conditions. It also manages `break` and `continue` labels.
    * **`GenerateImplementation(const std::string& dir)`:** This method clearly indicates the purpose of the visitor: generating C++ implementation files. It iterates through source files and writes out generated `.cc` and `.h` files.
    * **`GenerateMacroFunctionDeclaration(Macro* macro)` and `GenerateFunction(...)`:** These methods are responsible for generating C++ function declarations, handling different output types (CSA, CC, CCDebug).
    * **`LookupCallable(...)` and `LookupMethod(...)`:** These methods are crucial for resolving function calls and method calls. They handle overloading and generic specialization.
    * **`Visit(StructExpression* expr)`:** Handles the creation of struct instances, including initialization and type checking.
    * **`GenerateSetBitField(...)`:**  Deals with setting values in bitfield structures.
    * **`GetLocationReference(...)`:**  A suite of methods to determine how to access a value based on the expression (identifier, field access, element access, etc.). This is essential for generating correct memory access code.

4. **Identify Key Data Structures and Concepts:** Look for important data structures and concepts used within the methods.

    * **`TypeOracle`:**  Appears to be responsible for managing type information.
    * **`Assembler`:** Likely an interface for generating low-level assembly-like code or intermediate representation. The `Goto`, `Bind`, `Peek`, `Poke`, and `Emit` calls suggest this.
    * **`Block`:** Represents blocks of code, used for control flow in loops.
    * **`Binding<LocalValue>`, `Binding<LocalLabel>`:** Used for tracking local variables and labels within the current scope.
    * **`Signature`:** Represents the type signature of functions and methods.
    * **`Callable`, `Method`, `Macro`, `GenericCallable`:** Represent different kinds of callable entities in the Torque language.
    * **`LocationReference`:** Encapsulates different ways to refer to a memory location (variable, field, array element, etc.).
    * **`VisitResult`:** Represents the result of visiting an AST node, including its type and how it's represented in the generated code (on the stack, etc.).

5. **Infer Relationships and Interactions:**  Consider how the different methods and data structures interact. For example, the `Visit` methods use the `Assembler` to generate code, and `LookupCallable` is used to find the correct function to call in a `Visit` method.

6. **Connect to Torque's Purpose:** Recall that Torque is a language for writing built-in functions in V8. The generated C++ code interacts directly with V8's internal data structures and mechanisms. This context helps in understanding why certain internal functions like `AllocateFromNew` are used.

7. **Address Specific Instructions:**  Review the prompt's specific questions:

    * **`.tq` extension:** The code confirms that a `.tq` extension indicates a Torque source file.
    * **Relationship to JavaScript:**  The example of class instantiation with `new` in Torque and the corresponding JavaScript code demonstrates the connection.
    * **Code logic reasoning:** The `Visit(NewExpression*)` provides an example with assumptions about the `map` field.
    * **Common programming errors:** The error messages within the code (e.g., "break used outside of loop") point to common mistakes.

8. **Structure the Summary:** Organize the findings into a clear and concise summary, addressing the prompt's requirements. Start with the overall purpose and then detail the key functionalities.

9. **Refine and Elaborate:** Review the summary for clarity, accuracy, and completeness. Add details where necessary, such as explaining the purpose of specific methods or data structures. For example, explicitly mentioning the generation of `.cc`, `.h`, and `.inc` files.

By following this process, we can arrive at a comprehensive understanding of the `ImplementationVisitor`'s role and the functionalities implemented in the provided code snippet.
好的，我们来归纳一下 `v8/src/torque/implementation-visitor.cc` 这部分代码的功能。

**核心功能归纳：**

这部分 `ImplementationVisitor` 的代码主要负责 **将 Torque 语法中的表达式和语句转换成底层的 C++ 代码，并管理代码生成过程中的上下文信息**。  它关注于如何根据 Torque 的抽象语法树（AST）生成实际的 C++ 代码来实现其语义。

**具体功能点：**

1. **处理对象创建 (`Visit(NewExpression* expr)`)：**
   - 负责处理 `new` 关键字创建对象的 Torque 代码。
   - 检查类类型是否可以被 `new` 创建。
   - 处理构造函数的初始化列表，访问并处理初始化结果。
   - 特别处理 `map` 字段，对于外部类（`Extern`），要求构造函数显式传入 `Map` 参数；对于非外部类，自动插入 `Map` 参数。
   - 调用底层的分配函数 (`AllocateFromNew`) 来分配内存。
   - 调用 `InitializeClass` 来初始化对象的字段。
   - 最后将分配的结果转换为目标类型。

2. **处理控制流语句 (`Visit(BreakStatement* stmt)`, `Visit(ContinueStatement* stmt)`, `Visit(ForLoopStatement* stmt)`)：**
   - **`break` 和 `continue`：**  负责处理 `break` 和 `continue` 语句，通过跳转到对应的标签块来实现循环的中断和继续。会检查这些语句是否在循环内部使用。
   - **`for` 循环：**  负责处理 `for` 循环语句。
     - 创建循环体的代码块 (`body_block`) 和循环退出的代码块 (`exit_block`)。
     - 创建循环头的代码块 (`header_block`)。
     - 处理 `continue` 跳转的目标代码块 (`continue_block`)，如果存在 `action` 表达式，则跳转到 `action_block`，否则直接跳转到 `header_block`。
     - 处理循环条件 (`test`)，根据条件跳转到循环体或退出循环。
     - 递归访问循环体 (`stmt->body`)。
     - 如果有 `action` 表达式，则访问并执行。

3. **生成 C++ 实现 (`GenerateImplementation(const std::string& dir)`)：**
   - 负责将生成的 C++ 代码写入到文件中。
   - 遍历所有源文件，为每个 Torque 源文件生成对应的 C++ 实现文件 (`-tq-csa.cc`, `-tq-csa.h`, `-tq.inc`, `-tq-inl.inc`, `-tq.cc`)。
   - 处理内置头文件的包含。

4. **生成函数声明 (`GenerateMacroFunctionDeclaration(Macro* macro)`, `GenerateFunction(...)`)：**
   - 负责生成 C++ 函数的声明，包括宏函数和普通函数。
   - 设置函数的返回类型、参数列表。
   - 根据输出类型 (`OutputType`) 设置不同的参数，例如 `compiler::CodeAssemblerState*`。
   - 处理标签参数。

5. **查找和解析可调用对象 (`LookupCallable(...)`, `LookupMethod(...)`)：**
   - **`LookupCallable`：**  负责查找与给定的名称和参数类型匹配的可调用对象（函数、宏等）。支持泛型特化。如果找不到匹配的或者找到多个模糊匹配的，会报错。
   - **`LookupMethod`：**  专门用于查找类方法。

6. **处理结构体 (`Visit(StructExpression* expr)`)：**
   - 负责处理结构体的创建。
   - 计算结构体字段的值和类型。
   - 检查初始化列表是否符合结构体的定义。
   - 在栈上构建结构体。
   - 处理位域结构体，通过设置每个位域字段的值来初始化。

7. **处理位域 (`GenerateSetBitField(...)`)：**
   - 负责生成设置位域的代码。

8. **获取位置引用 (`GetLocationReference(...)`)：**
   - 负责获取表达式所代表的内存位置的引用。
   - 支持不同类型的表达式：标识符、字段访问、元素访问、解引用等。
   - 对于字段访问，会区分结构体字段和类字段，并处理常量字段和引用字段。
   - 对于元素访问，会处理堆切片。
   - 对于标识符，会查找本地变量或内置函数。

**与 JavaScript 的关系：**

这部分代码的功能与 JavaScript 中创建对象、控制程序流程的机制密切相关。

**JavaScript 示例：**

假设在 Torque 中定义了一个类 `MyClass`：

```torque
class MyClass extends Object {
  field: int32;
  constructor(p: int32) {
    this.field = p;
  }
}

var obj: MyClass = new MyClass(10);
```

`ImplementationVisitor` 的 `Visit(NewExpression* expr)` 方法就会处理 `new MyClass(10)` 这部分 Torque 代码，生成类似以下的 C++ 代码（简化）：

```c++
// ... 获取 MyClass 的 Map ...
compiler::TNode<MyClass> obj = TorqueGeneratedClass::Allocate<MyClass>(/* size */, map);
// ... 设置 obj->field 的值 ...
```

**代码逻辑推理示例：**

**假设输入 Torque 代码：**

```torque
class Point {
  x: int32;
  y: int32;
  constructor(a: int32, b: int32) {
    this.x = a;
    this.y = b;
  }
}

var p: Point = new Point(1, 2);
```

**`Visit(NewExpression* expr)` 方法的执行逻辑（简化）：**

1. 获取 `Point` 类的类型信息。
2. 检查 `Point` 是否可以被 `new` 创建（假设可以）。
3. 处理初始化列表 `(1, 2)`，分别访问表达式 `1` 和 `2`，得到类型为 `int32` 的值。
4. 获取 `Point` 类的 `map` 字段信息（假设是第一个字段）。
5. 调用 `GetInstanceTypeMap(POINT_TYPE)` 获取 `Point` 类的 `map`。
6. 调用 `AllocateFromNew` 分配 `Point` 对象所需的内存，传入大小和 `map`。
7. 调用 `InitializeClass` 初始化 `Point` 对象的 `x` 和 `y` 字段，将值 `1` 赋给 `x`，将值 `2` 赋给 `y`。
8. 返回新创建的 `Point` 对象。

**输出的 C++ 代码片段（简化）：**

```c++
compiler::TNode<Map> point_map = GetInstanceTypeMap(POINT_TYPE);
compiler::TNode<Point> p = AllocateFromNew<Point>(sizeof(Point), point_map);
p->x = 1;
p->y = 2;
```

**用户常见的编程错误：**

1. **在循环外部使用 `break` 或 `continue`：**  `ImplementationVisitor` 会检测到并在编译时报错，如代码中的 `ReportError("break used outside of loop");`。

   **错误示例 Torque 代码：**

   ```torque
   var x: int32 = 0;
   break; // 错误！
   ```

2. **构造函数缺少 `Map` 参数（对于外部类）：** 如果一个外部类的构造函数没有显式声明 `Map` 参数，`ImplementationVisitor` 会报错。

   **错误示例 Torque 代码（假设 `ExternalClass` 是一个外部类）：**

   ```torque
   class ExternalClass extends External {};

   var obj: ExternalClass = new ExternalClass(); // 错误！应该传入 Map
   ```

3. **为非外部类的构造函数指定 `Map` 参数：**  对于非外部类，`Map` 参数是自动插入的，用户不应显式指定。

   **错误示例 Torque 代码：**

   ```torque
   class InternalClass extends Object {};

   var obj: InternalClass = new InternalClass(%ObjectMap()); // 错误！不应传入 Map
   ```

**总结：**

总而言之，`v8/src/torque/implementation-visitor.cc` (这部分) 的核心职责是将高级的 Torque 语法转换为 V8 能够理解和执行的 C++ 代码，它处理了对象创建、控制流、函数调用、结构体和位域等关键的语言特性，并且在转换过程中进行类型检查和错误报告，帮助开发者避免常见的编程错误。它是 Torque 编译器中至关重要的一个组成部分。

Prompt: 
```
这是目录为v8/src/torque/implementation-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/implementation-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

"""
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
 
"""


```