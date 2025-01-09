Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `torque-parser.cc` file in the V8 JavaScript engine. The user also wants to understand how this code relates to Torque and JavaScript, including examples, logic, and common errors.

Here's a breakdown of the code's functionality:

1. **Annotation Handling:** The code defines a mechanism to parse and process annotations attached to Torque language elements. This includes checking for the presence of specific annotations and extracting their parameters (string or integer values). The `AnnotationSet` class is central to this.

2. **Conditional Compilation:** The `ProcessIfAnnotation` function enables conditional compilation based on build flags. Annotations like `@if` and `@ifnot` control whether certain code sections are included based on the values of these flags.

3. **Literal Parsing:** The code includes functions to parse integer (`YieldInt32`, `YieldIntegerLiteral`) and double (`YieldDouble`) literals from the input stream. It handles potential errors like invalid format or out-of-range values.

4. **Annotation Parameter Creation:** Functions `MakeStringAnnotationParameter` and `MakeIntAnnotationParameter` create `AnnotationParameter` objects from parsed values.

5. **Torque Builtin Declaration Parsing:** `MakeTorqueBuiltinDeclaration` parses declarations of Torque built-in functions. It extracts information like whether the builtin is transitioning, its JavaScript linkage, name, generic parameters, arguments, return type, and body. It also handles annotations specific to builtins like `@customInterfaceDescriptor` and `@incrementUseCounter`.

6. **Class Declaration Parsing:** `MakeClassDeclaration` parses class declarations, including handling various class flags defined via annotations. It also generates a corresponding constexpr type and a `Cast` specialization.

7. **Namespace, Specialization, Struct, and other Declaration Parsing:** The code includes functions to parse other Torque language constructs like namespaces, specializations, structs, bitfield structs, and C++ includes.

8. **Import Processing:** `ProcessTorqueImportDeclaration` handles import statements, ensuring that the imported files exist within the V8 source tree and are part of the compilation set.

9. **External Builtin and Runtime Parsing:** Functions to parse declarations of external builtins and runtime functions, which interface with C++ code.

10. **Type Expression Parsing:**  Functions to parse different kinds of type expressions, including basic types, function types, reference types, and union types.

11. **Statement Parsing:** Functions to parse different kinds of statements, including expression statements and if statements.

12. **Enum Declaration Parsing:** `MakeEnumDeclaration` handles the parsing of enum declarations, including generating both regular and constexpr versions of the enum and its entries.

**Relation to Torque and JavaScript:**

*   **Torque:** This code is a core part of the Torque parser. Torque is a domain-specific language used within V8 to generate efficient code for built-in functions and runtime components.
*   **JavaScript:** While this code doesn't directly execute JavaScript, the Torque code it parses is used to implement JavaScript features. For instance, built-in functions like `Array.prototype.push` or `Object.prototype.toString` are often implemented using Torque.

**Plan for summarizing the functionality:**

*   Focus on the main purpose: parsing Torque language elements.
*   Highlight key functionalities: annotation processing, literal parsing, declaration parsing (builtins, classes, enums, etc.), type expression parsing, and statement parsing.
*   Briefly mention the relationship with JavaScript and Torque.
这是目录为 `v8/src/torque/torque-parser.cc` 的 V8 源代码的第二部分。在第一部分的基础上，这部分代码延续了 Torque 语法解析的功能，专注于处理 Torque 语言中的各种声明和表达式，并根据解析结果构建抽象语法树 (AST) 节点。

以下是这部分代码的主要功能归纳：

1. **处理和提取注解信息 (Annotations):**
    *   定义了 `AnnotationSet` 类，用于存储和查询与代码元素关联的注解。
    *   提供了 `GetStringParam` 和 `GetIntParam` 方法，用于从注解中提取字符串和整数类型的参数。
    *   `ProcessIfAnnotation` 函数根据 `@if` 和 `@ifnot` 注解以及构建标志来决定是否继续处理后续的代码元素，实现了条件编译的功能。

2. **解析字面量 (Literals):**
    *   `YieldInt32` 函数用于解析 32 位整数，并处理解析失败和超出范围的情况。
    *   `YieldDouble` 函数用于解析双精度浮点数，并处理超出范围的情况。
    *   `YieldIntegerLiteral` 函数用于解析整数字面量，支持正负数，并处理解析失败和超出范围的情况，返回 `IntegerLiteral` 对象。

3. **创建注解参数 (Annotation Parameters):**
    *   `MakeStringAnnotationParameter` 和 `MakeIntAnnotationParameter` 函数分别用于创建字符串和整数类型的注解参数对象。

4. **解析 Torque 内建函数声明 (Builtin Declarations):**
    *   `MakeTorqueBuiltinDeclaration` 函数解析 `builtin` 关键字声明的函数。
    *   它处理与内建函数相关的注解，例如 `@customInterfaceDescriptor` 和 `@incrementUseCounter`。
    *   它提取内建函数的属性，如是否是 `transitioning`，是否与 JavaScript 关联 (`javascript_linkage`)，函数名，泛型参数，参数列表，返回类型和函数体。
    *   对于泛型内建函数，会创建 `GenericCallableDeclaration` 节点。

5. **处理类声明相关的注解 (Class Declaration Annotations):**
    *   `MakeInstanceTypeConstraints` 函数根据注解信息创建 `InstanceTypeConstraints` 对象，用于约束类的实例类型。
    *   `MakeClassDeclaration` 函数处理类声明，包括解析各种与类相关的注解，例如 `@abstract`, `@export`, `@generateUniqueMap` 等，并根据注解设置 `ClassFlags`。

6. **解析类的主体 (Class Body):**
    *   `MakeClassBody` 函数解析类定义中的方法和字段。

7. **解析类声明 (Class Declaration):**
    *   `MakeClassDeclaration` 函数解析 `class` 或 `shape` 关键字声明的类。
    *   它提取类的名称，继承关系 (`extends`)，是否是外部类 (`extern`)，是否是瞬态类 (`transient`)，以及类的主体。
    *   它会根据注解生成相应的 `ClassDeclaration` 节点，并为 constexpr 版本生成 `AbstractTypeDeclaration` 节点。
    *   对于非抽象类，还会生成 `Cast` 特化声明，用于类型转换。

8. **解析命名空间声明 (Namespace Declaration):**
    *   `MakeNamespaceDeclaration` 函数解析 `namespace` 关键字声明的命名空间，包含其中的各种声明。

9. **解析特化声明 (Specialization Declaration):**
    *   `MakeSpecializationDeclaration` 函数解析 `transitioning` 关键字后的特化声明，包括泛型参数、参数列表、返回类型、标签和函数体。

10. **解析结构体声明 (Struct Declaration):**
    *   `MakeStructDeclaration` 函数解析 `struct` 关键字声明的结构体，包括泛型参数、方法和字段。

11. **解析位域结构体声明 (BitFieldStruct Declaration):**
    *   `MakeBitFieldStructDeclaration` 函数解析用于定义位域的结构体声明。

12. **解析 C++ 引入声明 (Cpp Include Declaration):**
    *   `MakeCppIncludeDeclaration` 函数解析 `#include` 声明，用于引入 C++ 头文件。

13. **处理 Torque 导入声明 (Torque Import Declaration):**
    *   `ProcessTorqueImportDeclaration` 函数处理 `import` 声明，用于导入其他的 Torque 源文件。它会检查导入的文件是否存在，并将其添加到当前文件的导入列表中。

14. **解析外部内建函数声明 (External Builtin Declaration):**
    *   `MakeExternalBuiltin` 函数解析 `extern builtin` 关键字声明的外部内建函数，这些函数通常由 C++ 实现。

15. **解析外部运行时函数声明 (External Runtime Declaration):**
    *   `MakeExternalRuntime` 函数解析 `extern runtime` 关键字声明的外部运行时函数，这些函数是 V8 运行时的 C++ 函数。

16. **处理字符串字面量 (String Literal Unquote):**
    *   `StringLiteralUnquoteAction` 函数用于处理字符串字面量，可能涉及到去除引号等操作。

17. **解析类型表达式 (Type Expressions):**
    *   `MakeBasicTypeExpression` 函数解析基本的类型表达式，包括命名空间限定符和泛型参数。
    *   `MakeFunctionTypeExpression` 函数解析函数类型表达式，包括参数类型和返回类型。
    *   `MakeReferenceTypeExpression` 函数解析引用类型表达式，包括是否是常量引用。
    *   `MakeUnionTypeExpression` 函数解析联合类型表达式。

18. **解析泛型参数 (Generic Parameter):**
    *   `MakeGenericParameter` 函数解析泛型参数，包括参数名和约束。

19. **解析语句 (Statements):**
    *   `MakeExpressionStatement` 函数解析表达式语句。
    *   `MakeIfStatement` 函数解析 `if` 语句，包括 `constexpr` 修饰符。

20. **解析枚举声明 (Enum Declaration):**
    *   `MakeEnumDeclaration` 函数解析 `enum` 关键字声明的枚举类型。
    *   它支持 `extern` 枚举，并处理枚举的基类型、constexpr 生成器和枚举条目。
    *   对于 `open` 和 `closed` 枚举，会生成不同的类型声明和命名空间结构。
    *   它还会为 constexpr 版本的枚举及其条目生成相应的声明。

21. **解析类型切换语句 (Typeswitch Statement):**
    *   `MakeTypeswitchStatement` 函数开始处理 `typeswitch` 语句的解析，但代码片段在此处被截断。

**与 JavaScript 的关系:**

这部分代码是 Torque 编译器的组成部分，Torque 是一种用于编写 V8 内部函数（例如内置函数和运行时函数）的语言。通过解析 Torque 代码，V8 可以生成高效的 C++ 代码来执行 JavaScript 的各种操作。例如，`MakeTorqueBuiltinDeclaration` 解析的内建函数声明通常对应着 JavaScript 中 `Array.prototype.push` 或 `Object.toString` 等内置方法的实现逻辑。

**JavaScript 示例 (概念性):**

虽然 `torque-parser.cc` 本身不包含 JavaScript 代码，但它解析的 Torque 代码最终会影响 JavaScript 的执行。例如，一个用 Torque 编写的内建函数可能如下所示（简化）：

```torque
builtin ArrayPush<T>(receiver: FixedArray, value: T): Number {
  // ... Torque 实现 ...
  return new_length;
}
```

这个 Torque 内建函数 `ArrayPush` 对应于 JavaScript 中 `Array.prototype.push` 方法的功能。当 JavaScript 代码执行 `[1, 2].push(3)` 时，V8 会调用由 Torque 编译生成的 C++ 代码来完成数组元素的添加操作。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (Torque 源代码片段):**

```torque
builtin Foo(a: int32, b: String): Boolean {
  return true;
}
```

**输出 (概念性的 AST 节点结构):**

```
TorqueBuiltinDeclaration {
  transitioning: false,
  javascript_linkage: false,
  name: "Foo",
  generic_parameters: [],
  args: [
    Parameter { name: "a", type: "int32" },
    Parameter { name: "b", type: "String" }
  ],
  return_type: "Boolean",
  body: BlockStatement {
    statements: [
      ReturnStatement {
        expression: IdentifierExpression { name: "true" }
      }
    ]
  }
}
```

**用户常见的编程错误 (在 Torque 中):**

1. **类型不匹配:** 在 Torque 函数调用或赋值时，提供的参数类型与声明的参数类型不符。例如，向期望 `int32` 类型的参数传递了一个字符串。
    ```torque
    // 错误示例
    builtin Bar(x: int32): void {}
    var str: String = "hello";
    Bar(str); // 类型错误：String 不能隐式转换为 int32
    ```

2. **未定义的标识符:** 尝试使用未声明的变量或函数名。
    ```torque
    // 错误示例
    builtin Baz(): void {
      unknown_variable = 10; // unknown_variable 未声明
    }
    ```

3. **违反命名约定:** Torque 对不同的语言元素有特定的命名约定（例如，类名使用 UpperCamelCase，命名空间使用 snake\_case）。不遵守这些约定会导致解析错误。
    ```torque
    // 错误示例
    class myclass {} // 错误：类名应使用 UpperCamelCase (MyClass)
    ```

4. **注解使用错误:** 错误地使用或放置注解，例如在不支持特定注解的地方使用了它，或者注解参数的类型不正确。
    ```torque
    // 错误示例
    @if("DEBUG_MODE") // 假设 DEBUG_MODE 不是一个有效的构建标志
    builtin Qux(): void {}
    ```

总而言之，这部分 `torque-parser.cc` 的代码负责将 Torque 源代码解析成 V8 可以理解的抽象语法树，是 Torque 编译器的核心组成部分，其解析结果直接影响着 JavaScript 功能的实现效率和正确性。

Prompt: 
```
这是目录为v8/src/torque/torque-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/torque-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
.first.string_value;
  }
  std::optional<int32_t> GetIntParam(const std::string& s) const {
    auto it = map_.find(s);
    if (it == map_.end()) {
      return {};
    }
    if (!it->second.first.is_int) {
      Error("Annotation ", s, " requires an int parameter but has a string")
          .Position(it->second.second);
    }
    return it->second.first.int_value;
  }

 private:
  std::set<std::string> set_;
  std::map<std::string, std::pair<AnnotationParameter, SourcePosition>> map_;
};

bool ProcessIfAnnotation(ParseResultIterator* child_results) {
  AnnotationSet annotations(child_results, {},
                            {ANNOTATION_IF, ANNOTATION_IFNOT});
  if (std::optional<std::string> condition =
          annotations.GetStringParam(ANNOTATION_IF)) {
    if (!BuildFlags::GetFlag(*condition, ANNOTATION_IF)) return false;
  }
  if (std::optional<std::string> condition =
          annotations.GetStringParam(ANNOTATION_IFNOT)) {
    if (BuildFlags::GetFlag(*condition, ANNOTATION_IFNOT)) return false;
  }
  return true;
}

std::optional<ParseResult> YieldInt32(ParseResultIterator* child_results) {
  std::string value = child_results->matched_input().ToString();
  size_t num_chars_converted = 0;
  int result = 0;
  try {
    result = std::stoi(value, &num_chars_converted, 0);
  } catch (const std::invalid_argument&) {
    Error("Expected an integer");
    return ParseResult{result};
  } catch (const std::out_of_range&) {
    Error("Integer out of 32-bit range");
    return ParseResult{result};
  }
  // Tokenizer shouldn't have included extra trailing characters.
  DCHECK_EQ(num_chars_converted, value.size());
  return ParseResult{result};
}

std::optional<ParseResult> YieldDouble(ParseResultIterator* child_results) {
  std::string value = child_results->matched_input().ToString();
  size_t num_chars_converted = 0;
  double result = 0;
  try {
    result = std::stod(value, &num_chars_converted);
  } catch (const std::out_of_range&) {
    Error("double literal out-of-range");
    return ParseResult{result};
  }
  // Tokenizer shouldn't have included extra trailing characters.
  DCHECK_EQ(num_chars_converted, value.size());
  return ParseResult{result};
}

std::optional<ParseResult> YieldIntegerLiteral(
    ParseResultIterator* child_results) {
  std::string value = child_results->matched_input().ToString();
  // Consume a leading minus.
  bool negative = false;
  if (!value.empty() && value[0] == '-') {
    negative = true;
    value = value.substr(1);
  }
  uint64_t absolute_value;
  try {
    size_t parsed = 0;
    absolute_value = std::stoull(value, &parsed, 0);
    DCHECK_EQ(parsed, value.size());
  } catch (const std::invalid_argument&) {
    Error("integer literal could not be parsed").Throw();
  } catch (const std::out_of_range&) {
    Error("integer literal value out of range").Throw();
  }
  return ParseResult(IntegerLiteral(negative, absolute_value));
}

std::optional<ParseResult> MakeStringAnnotationParameter(
    ParseResultIterator* child_results) {
  std::string value = child_results->NextAs<std::string>();
  AnnotationParameter result{value, 0, false};
  return ParseResult{result};
}

std::optional<ParseResult> MakeIntAnnotationParameter(
    ParseResultIterator* child_results) {
  int32_t value = child_results->NextAs<int32_t>();
  AnnotationParameter result{"", value, true};
  return ParseResult{result};
}

int GetAnnotationValue(const AnnotationSet& annotations, const char* name,
                       int default_value) {
  auto opt_value = annotations.GetIntParam(name);
  return opt_value.has_value() ? *opt_value : default_value;
}

std::optional<ParseResult> MakeTorqueBuiltinDeclaration(
    ParseResultIterator* child_results) {
  AnnotationSet annotations(child_results,
                            {ANNOTATION_CUSTOM_INTERFACE_DESCRIPTOR},
                            {ANNOTATION_IF, ANNOTATION_INCREMENT_USE_COUNTER});
  const bool has_custom_interface_descriptor =
      annotations.Contains(ANNOTATION_CUSTOM_INTERFACE_DESCRIPTOR);
  std::optional<std::string> use_counter_name =
      annotations.GetStringParam(ANNOTATION_INCREMENT_USE_COUNTER);
  auto transitioning = child_results->NextAs<bool>();
  auto javascript_linkage = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  if (!IsUpperCamelCase(name->value)) {
    NamingConventionError("Builtin", name, "UpperCamelCase");
  }

  auto generic_parameters = child_results->NextAs<GenericParameters>();
  LintGenericParameters(generic_parameters);

  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  auto body = child_results->NextAs<std::optional<Statement*>>();
  CallableDeclaration* declaration = MakeNode<TorqueBuiltinDeclaration>(
      transitioning, javascript_linkage, name, args, return_type,
      has_custom_interface_descriptor, use_counter_name, body);
  Declaration* result = declaration;
  if (generic_parameters.empty()) {
    if (!body) ReportError("A non-generic declaration needs a body.");
  } else {
    result = MakeNode<GenericCallableDeclaration>(std::move(generic_parameters),
                                                  declaration);
  }
  if (use_counter_name && !body) {
    ReportError("@incrementUseCounter needs a body.");
  }
  std::vector<Declaration*> results;
  if (std::optional<std::string> condition =
          annotations.GetStringParam(ANNOTATION_IF)) {
    if (!BuildFlags::GetFlag(*condition, ANNOTATION_IF)) {
      return ParseResult{std::move(results)};
    }
  }
  results.push_back(result);
  return ParseResult{std::move(results)};
}

InstanceTypeConstraints MakeInstanceTypeConstraints(
    const AnnotationSet& annotations) {
  InstanceTypeConstraints result;
  result.value =
      GetAnnotationValue(annotations, ANNOTATION_INSTANCE_TYPE_VALUE, -1);
  result.num_flags_bits = GetAnnotationValue(
      annotations, ANNOTATION_RESERVE_BITS_IN_INSTANCE_TYPE, -1);
  return result;
}

std::optional<ParseResult> MakeClassBody(ParseResultIterator* child_results) {
  auto methods = child_results->NextAs<std::vector<Declaration*>>();
  auto fields = child_results->NextAs<std::vector<ClassFieldExpression>>();
  std::optional<ClassBody*> result =
      MakeNode<ClassBody>(std::move(methods), std::move(fields));
  return ParseResult(result);
}

std::optional<ParseResult> MakeClassDeclaration(
    ParseResultIterator* child_results) {
  AnnotationSet annotations(
      child_results,
      {ANNOTATION_ABSTRACT, ANNOTATION_HAS_SAME_INSTANCE_TYPE_AS_PARENT,
       ANNOTATION_DO_NOT_GENERATE_CPP_CLASS, ANNOTATION_CUSTOM_CPP_CLASS,
       ANNOTATION_CUSTOM_MAP, ANNOTATION_GENERATE_BODY_DESCRIPTOR,
       ANNOTATION_EXPORT, ANNOTATION_DO_NOT_GENERATE_CAST,
       ANNOTATION_GENERATE_UNIQUE_MAP, ANNOTATION_GENERATE_FACTORY_FUNCTION,
       ANNOTATION_HIGHEST_INSTANCE_TYPE_WITHIN_PARENT,
       ANNOTATION_LOWEST_INSTANCE_TYPE_WITHIN_PARENT,
       ANNOTATION_CPP_OBJECT_DEFINITION,
       ANNOTATION_CPP_OBJECT_LAYOUT_DEFINITION},
      {ANNOTATION_RESERVE_BITS_IN_INSTANCE_TYPE,
       ANNOTATION_INSTANCE_TYPE_VALUE});
  ClassFlags flags = ClassFlag::kNone;
  if (annotations.Contains(ANNOTATION_ABSTRACT)) {
    flags |= ClassFlag::kAbstract;
  }
  if (annotations.Contains(ANNOTATION_HAS_SAME_INSTANCE_TYPE_AS_PARENT)) {
    flags |= ClassFlag::kHasSameInstanceTypeAsParent;
  }
  bool do_not_generate_cpp_class =
      annotations.Contains(ANNOTATION_DO_NOT_GENERATE_CPP_CLASS);
  if (annotations.Contains(ANNOTATION_CUSTOM_CPP_CLASS)) {
    Error(
        "@customCppClass is deprecated. Use 'extern' instead. "
        "@generateBodyDescriptor, @generateUniqueMap, and "
        "@generateFactoryFunction accomplish most of what '@export "
        "@customCppClass' used to.");
  }
  if (annotations.Contains(ANNOTATION_CUSTOM_MAP)) {
    Error(
        "@customMap is deprecated. Generating a unique map is opt-in now using "
        "@generateUniqueMap.");
  }
  if (annotations.Contains(ANNOTATION_DO_NOT_GENERATE_CAST)) {
    flags |= ClassFlag::kDoNotGenerateCast;
  }
  if (annotations.Contains(ANNOTATION_GENERATE_BODY_DESCRIPTOR)) {
    flags |= ClassFlag::kGenerateBodyDescriptor;
  }
  if (annotations.Contains(ANNOTATION_GENERATE_UNIQUE_MAP)) {
    flags |= ClassFlag::kGenerateUniqueMap;
  }
  if (annotations.Contains(ANNOTATION_GENERATE_FACTORY_FUNCTION)) {
    flags |= ClassFlag::kGenerateFactoryFunction;
  }
  if (annotations.Contains(ANNOTATION_EXPORT)) {
    flags |= ClassFlag::kExport;
  }
  if (annotations.Contains(ANNOTATION_HIGHEST_INSTANCE_TYPE_WITHIN_PARENT)) {
    flags |= ClassFlag::kHighestInstanceTypeWithinParent;
  }
  if (annotations.Contains(ANNOTATION_LOWEST_INSTANCE_TYPE_WITHIN_PARENT)) {
    flags |= ClassFlag::kLowestInstanceTypeWithinParent;
  }
  if (annotations.Contains(ANNOTATION_CPP_OBJECT_DEFINITION)) {
    flags |= ClassFlag::kCppObjectDefinition;
  }
  if (annotations.Contains(ANNOTATION_CPP_OBJECT_LAYOUT_DEFINITION)) {
    flags |= ClassFlag::kCppObjectLayoutDefinition;
  }

  auto is_extern = child_results->NextAs<bool>();
  if (is_extern) flags |= ClassFlag::kExtern;
  auto transient = child_results->NextAs<bool>();
  if (transient) flags |= ClassFlag::kTransient;
  std::string kind = child_results->NextAs<Identifier*>()->value;
  if (kind == "shape") {
    flags |= ClassFlag::kIsShape;
    flags |= ClassFlag::kTransient;
    flags |= ClassFlag::kHasSameInstanceTypeAsParent;
    flags |= ClassFlag::kDoNotGenerateCast;
  } else {
    DCHECK_EQ(kind, "class");
  }
  auto name = child_results->NextAs<Identifier*>();
  if (!IsValidTypeName(name->value)) {
    NamingConventionError("Type", name, "UpperCamelCase");
  }
  auto extends = child_results->NextAs<TypeExpression*>();
  if (!BasicTypeExpression::DynamicCast(extends)) {
    ReportError("Expected type name in extends clause.");
  }
  auto generates = child_results->NextAs<std::optional<std::string>>();
  auto body = child_results->NextAs<std::optional<ClassBody*>>();
  std::vector<Declaration*> methods;
  std::vector<ClassFieldExpression> fields_raw;
  if (body.has_value()) {
    methods = (*body)->methods;
    fields_raw = (*body)->fields;
  } else {
    flags |= ClassFlag::kUndefinedLayout;
  }

  if (is_extern && body.has_value()) {
    if (!do_not_generate_cpp_class) {
      flags |= ClassFlag::kGenerateCppClassDefinitions;
    }
  } else if (do_not_generate_cpp_class) {
    Lint("Annotation @doNotGenerateCppClass has no effect");
  }

  // Filter to only include fields that should be present based on decoration.
  std::vector<ClassFieldExpression> fields;
  std::copy_if(
      fields_raw.begin(), fields_raw.end(), std::back_inserter(fields),
      [](const ClassFieldExpression& exp) {
        for (const ConditionalAnnotation& condition : exp.conditions) {
          if (condition.type == ConditionalAnnotationType::kPositive
                  ? !BuildFlags::GetFlag(condition.condition, ANNOTATION_IF)
                  : BuildFlags::GetFlag(condition.condition,
                                        ANNOTATION_IFNOT)) {
            return false;
          }
        }
        return true;
      });

  std::vector<Declaration*> result;

  result.push_back(MakeNode<ClassDeclaration>(
      name, flags, extends, generates, std::move(methods), std::move(fields),
      MakeInstanceTypeConstraints(annotations)));

  Identifier* constexpr_name =
      MakeNode<Identifier>(CONSTEXPR_TYPE_PREFIX + name->value);
  constexpr_name->pos = name->pos;
  TypeExpression* constexpr_extends = AddConstexpr(extends);
  AbstractTypeFlags abstract_type_flags(AbstractTypeFlag::kConstexpr);
  if (transient) abstract_type_flags |= AbstractTypeFlag::kTransient;
  TypeDeclaration* constexpr_decl = MakeNode<AbstractTypeDeclaration>(
      constexpr_name, abstract_type_flags, constexpr_extends,
      generates ? UnwrapTNodeTypeName(*generates) : name->value);
  constexpr_decl->pos = name->pos;
  result.push_back(constexpr_decl);

  if ((flags & ClassFlag::kDoNotGenerateCast) == 0 &&
      (flags & ClassFlag::kIsShape) == 0) {
    ParameterList parameters;
    parameters.names.push_back(MakeNode<Identifier>("obj"));
    parameters.types.push_back(MakeNode<BasicTypeExpression>(
        std::vector<std::string>{}, MakeNode<Identifier>("HeapObject"),
        std::vector<TypeExpression*>{}));
    LabelAndTypesVector labels;
    labels.push_back(LabelAndTypes{MakeNode<Identifier>("CastError"),
                                   std::vector<TypeExpression*>{}});

    TypeExpression* class_type = MakeNode<BasicTypeExpression>(
        std::vector<std::string>{}, name, std::vector<TypeExpression*>{});

    std::vector<std::string> namespace_qualification{
        TORQUE_INTERNAL_NAMESPACE_STRING};

    IdentifierExpression* internal_downcast_target =
        MakeNode<IdentifierExpression>(
            std::move(namespace_qualification),
            MakeNode<Identifier>("DownCastForTorqueClass"),
            std::vector<TypeExpression*>{class_type});
    IdentifierExpression* internal_downcast_otherwise =
        MakeNode<IdentifierExpression>(std::vector<std::string>{},
                                       MakeNode<Identifier>("CastError"));

    Expression* argument = MakeNode<IdentifierExpression>(
        std::vector<std::string>{}, MakeNode<Identifier>("obj"));

    auto value = MakeCall(internal_downcast_target, std::nullopt,
                          std::vector<Expression*>{argument},
                          std::vector<Statement*>{MakeNode<ExpressionStatement>(
                              internal_downcast_otherwise)});

    auto cast_body = MakeNode<ReturnStatement>(value);

    std::vector<TypeExpression*> generic_parameters;
    generic_parameters.push_back(MakeNode<BasicTypeExpression>(
        std::vector<std::string>{}, name, std::vector<TypeExpression*>{}));

    Declaration* specialization = MakeNode<SpecializationDeclaration>(
        false, MakeNode<Identifier>("Cast"), std::move(generic_parameters),
        std::move(parameters), class_type, std::move(labels), cast_body);
    result.push_back(specialization);
  }

  return ParseResult{std::move(result)};
}

std::optional<ParseResult> MakeNamespaceDeclaration(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<std::string>();
  if (!IsSnakeCase(name)) {
    NamingConventionError("Namespace", name, "snake_case");
  }
  auto declarations = child_results->NextAs<std::vector<Declaration*>>();
  Declaration* result =
      MakeNode<NamespaceDeclaration>(std::move(name), std::move(declarations));
  return ParseResult{result};
}

std::optional<ParseResult> MakeSpecializationDeclaration(
    ParseResultIterator* child_results) {
  auto transitioning = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  auto generic_parameters =
      child_results->NextAs<std::vector<TypeExpression*>>();
  auto parameters = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  auto labels = child_results->NextAs<LabelAndTypesVector>();
  auto body = child_results->NextAs<Statement*>();
  CheckNotDeferredStatement(body);
  Declaration* result = MakeNode<SpecializationDeclaration>(
      transitioning, std::move(name), std::move(generic_parameters),
      std::move(parameters), return_type, std::move(labels), body);
  return ParseResult{result};
}

std::optional<ParseResult> MakeStructDeclaration(
    ParseResultIterator* child_results) {
  bool is_export = HasExportAnnotation(child_results, "Struct");

  StructFlags flags = StructFlag::kNone;
  if (is_export) flags |= StructFlag::kExport;

  auto name = child_results->NextAs<Identifier*>();
  if (!IsValidTypeName(name->value)) {
    NamingConventionError("Struct", name, "UpperCamelCase");
  }
  auto generic_parameters = child_results->NextAs<GenericParameters>();
  LintGenericParameters(generic_parameters);
  auto methods = child_results->NextAs<std::vector<Declaration*>>();
  auto fields = child_results->NextAs<std::vector<StructFieldExpression>>();
  TypeDeclaration* struct_decl = MakeNode<StructDeclaration>(
      flags, name, std::move(methods), std::move(fields));
  Declaration* result = struct_decl;
  if (!generic_parameters.empty()) {
    result = MakeNode<GenericTypeDeclaration>(std::move(generic_parameters),
                                              struct_decl);
  }
  return ParseResult{result};
}

std::optional<ParseResult> MakeBitFieldStructDeclaration(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  if (!IsValidTypeName(name->value)) {
    NamingConventionError("Bitfield struct", name, "UpperCamelCase");
  }
  auto extends = child_results->NextAs<TypeExpression*>();
  auto fields = child_results->NextAs<std::vector<BitFieldDeclaration>>();
  Declaration* decl =
      MakeNode<BitFieldStructDeclaration>(name, extends, std::move(fields));
  return ParseResult{decl};
}

std::optional<ParseResult> MakeCppIncludeDeclaration(
    ParseResultIterator* child_results) {
  auto include_path = child_results->NextAs<std::string>();
  Declaration* result =
      MakeNode<CppIncludeDeclaration>(std::move(include_path));
  return ParseResult{result};
}

std::optional<ParseResult> ProcessTorqueImportDeclaration(
    ParseResultIterator* child_results) {
  auto import_path = child_results->NextAs<std::string>();
  if (!SourceFileMap::FileRelativeToV8RootExists(import_path)) {
    Error("File '", import_path, "' not found.");
  }

  auto import_id = SourceFileMap::GetSourceId(import_path);
  if (!import_id.IsValid()) {
    // TODO(szuend): Instead of reporting and error. Queue the file up
    //               for compilation.
    Error("File '", import_path, "'is not part of the source set.").Throw();
  }

  CurrentAst::Get().DeclareImportForCurrentFile(import_id);

  return std::nullopt;
}

std::optional<ParseResult> MakeExternalBuiltin(
    ParseResultIterator* child_results) {
  auto transitioning = child_results->NextAs<bool>();
  auto js_linkage = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  auto generic_parameters = child_results->NextAs<GenericParameters>();
  LintGenericParameters(generic_parameters);

  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  Declaration* result = MakeNode<ExternalBuiltinDeclaration>(
      transitioning, js_linkage, name, args, return_type);
  if (!generic_parameters.empty()) {
    Error("External builtins cannot be generic.");
  }
  return ParseResult{result};
}

std::optional<ParseResult> MakeExternalRuntime(
    ParseResultIterator* child_results) {
  auto transitioning = child_results->NextAs<bool>();
  auto name = child_results->NextAs<Identifier*>();
  auto args = child_results->NextAs<ParameterList>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  Declaration* result = MakeNode<ExternalRuntimeDeclaration>(
      transitioning, name, args, return_type);
  return ParseResult{result};
}

std::optional<ParseResult> StringLiteralUnquoteAction(
    ParseResultIterator* child_results) {
  return ParseResult{
      StringLiteralUnquote(child_results->NextAs<std::string>())};
}

std::optional<ParseResult> MakeBasicTypeExpression(
    ParseResultIterator* child_results) {
  auto namespace_qualification =
      child_results->NextAs<std::vector<std::string>>();
  auto is_constexpr = child_results->NextAs<bool>();
  auto name = child_results->NextAs<std::string>();
  auto generic_arguments =
      child_results->NextAs<std::vector<TypeExpression*>>();
  TypeExpression* result = MakeNode<BasicTypeExpression>(
      std::move(namespace_qualification),
      MakeNode<Identifier>(is_constexpr ? GetConstexprName(name)
                                        : std::move(name)),
      std::move(generic_arguments));
  return ParseResult{result};
}

std::optional<ParseResult> MakeFunctionTypeExpression(
    ParseResultIterator* child_results) {
  auto parameters = child_results->NextAs<std::vector<TypeExpression*>>();
  auto return_type = child_results->NextAs<TypeExpression*>();
  TypeExpression* result =
      MakeNode<FunctionTypeExpression>(std::move(parameters), return_type);
  return ParseResult{result};
}

std::optional<ParseResult> MakeReferenceTypeExpression(
    ParseResultIterator* child_results) {
  auto is_const = child_results->NextAs<bool>();
  auto referenced_type = child_results->NextAs<TypeExpression*>();
  std::vector<std::string> namespace_qualification{
      TORQUE_INTERNAL_NAMESPACE_STRING};
  std::vector<TypeExpression*> generic_arguments{referenced_type};
  TypeExpression* result = MakeNode<BasicTypeExpression>(
      std::move(namespace_qualification),
      MakeNode<Identifier>(is_const ? CONST_REFERENCE_TYPE_STRING
                                    : MUTABLE_REFERENCE_TYPE_STRING),
      std::move(generic_arguments));
  return ParseResult{result};
}

std::optional<ParseResult> MakeUnionTypeExpression(
    ParseResultIterator* child_results) {
  auto a = child_results->NextAs<TypeExpression*>();
  auto b = child_results->NextAs<TypeExpression*>();
  TypeExpression* result = MakeNode<UnionTypeExpression>(a, b);
  return ParseResult{result};
}

std::optional<ParseResult> MakeGenericParameter(
    ParseResultIterator* child_results) {
  auto name = child_results->NextAs<Identifier*>();
  auto constraint = child_results->NextAs<std::optional<TypeExpression*>>();
  return ParseResult{GenericParameter{name, constraint}};
}

std::optional<ParseResult> MakeExpressionStatement(
    ParseResultIterator* child_results) {
  auto expression = child_results->NextAs<Expression*>();
  Statement* result = MakeNode<ExpressionStatement>(expression);
  return ParseResult{result};
}

std::optional<ParseResult> MakeIfStatement(ParseResultIterator* child_results) {
  auto is_constexpr = child_results->NextAs<bool>();
  auto condition = child_results->NextAs<Expression*>();
  auto if_true = child_results->NextAs<Statement*>();
  auto if_false = child_results->NextAs<std::optional<Statement*>>();

  if (if_false && !(BlockStatement::DynamicCast(if_true) &&
                    (BlockStatement::DynamicCast(*if_false) ||
                     IfStatement::DynamicCast(*if_false)))) {
    ReportError("if-else statements require curly braces");
  }

  if (is_constexpr) {
    CheckNotDeferredStatement(if_true);
    if (if_false) CheckNotDeferredStatement(*if_false);
  }

  Statement* result =
      MakeNode<IfStatement>(is_constexpr, condition, if_true, if_false);
  return ParseResult{result};
}

std::optional<ParseResult> MakeEnumDeclaration(
    ParseResultIterator* child_results) {
  const bool is_extern = child_results->NextAs<bool>();
  auto name_identifier = child_results->NextAs<Identifier*>();
  auto name = name_identifier->value;
  auto base_type_expression =
      child_results->NextAs<std::optional<TypeExpression*>>();
  auto constexpr_generates_opt =
      child_results->NextAs<std::optional<std::string>>();
  auto entries = child_results->NextAs<std::vector<EnumEntry>>();
  const bool is_open = child_results->NextAs<bool>();
  CurrentSourcePosition::Scope current_source_position(
      child_results->matched_input().pos);

  if (!is_extern) {
    ReportError("non-extern enums are not supported yet");
  }

  if (!IsValidTypeName(name)) {
    NamingConventionError("Type", name, "UpperCamelCase");
  }

  if (constexpr_generates_opt && *constexpr_generates_opt == name) {
    Lint("Unnecessary 'constexpr' clause for enum ", name);
  }
  auto constexpr_generates =
      constexpr_generates_opt ? *constexpr_generates_opt : name;
  const bool generate_nonconstexpr = base_type_expression.has_value();

  std::vector<Declaration*> result;
  // Build non-constexpr types.
  if (generate_nonconstexpr) {
    DCHECK(base_type_expression.has_value());

    if (is_open) {
      // For open enumerations, we define an abstract type and inherit all
      // entries' types from that:
      //   type Enum extends Base;
      //   namespace Enum {
      //     type kEntry0 extends Enum;
      //     ...
      //     type kEntryN extends Enum;
      //   }
      auto type_decl = MakeNode<AbstractTypeDeclaration>(
          name_identifier, AbstractTypeFlag::kNone, base_type_expression,
          std::nullopt);

      TypeExpression* name_type_expression =
          MakeNode<BasicTypeExpression>(name_identifier);
      name_type_expression->pos = name_identifier->pos;

      std::vector<Declaration*> entry_decls;
      entry_decls.reserve(entries.size());
      for (const auto& entry : entries) {
        entry_decls.push_back(MakeNode<AbstractTypeDeclaration>(
            entry.name, AbstractTypeFlag::kNone,
            entry.type.value_or(name_type_expression), std::nullopt));
      }

      result.push_back(type_decl);
      result.push_back(
          MakeNode<NamespaceDeclaration>(name, std::move(entry_decls)));
    } else {
      // For closed enumerations, we define abstract types for all entries and
      // define the enumeration as a union of those:
      //   namespace Enum {
      //     type kEntry0 extends Base;
      //     ...
      //     type kEntryN extends Base;
      //   }
      //   type Enum = Enum::kEntry0 | ... | Enum::kEntryN;
      TypeExpression* union_type = nullptr;
      std::vector<Declaration*> entry_decls;
      for (const auto& entry : entries) {
        entry_decls.push_back(MakeNode<AbstractTypeDeclaration>(
            entry.name, AbstractTypeFlag::kNone,
            entry.type.value_or(*base_type_expression), std::nullopt));

        auto entry_type = MakeNode<BasicTypeExpression>(
            std::vector<std::string>{name}, entry.name,
            std::vector<TypeExpression*>{});
        if (union_type) {
          union_type = MakeNode<UnionTypeExpression>(union_type, entry_type);
        } else {
          union_type = entry_type;
        }
      }

      result.push_back(
          MakeNode<NamespaceDeclaration>(name, std::move(entry_decls)));
      result.push_back(
          MakeNode<TypeAliasDeclaration>(name_identifier, union_type));
    }
  }

  // Build constexpr types.
  {
    // The constexpr entries inherit from an abstract enumeration type:
    //   type constexpr Enum extends constexpr Base;
    //   namespace Enum {
    //     type constexpr kEntry0 extends constexpr Enum;
    //     ...
    //     type constexpr kEntry1 extends constexpr Enum;
    //   }
    Identifier* constexpr_type_identifier =
        MakeNode<Identifier>(std::string(CONSTEXPR_TYPE_PREFIX) + name);
    TypeExpression* constexpr_type_expression = MakeNode<BasicTypeExpression>(
        MakeNode<Identifier>(std::string(CONSTEXPR_TYPE_PREFIX) + name));
    std::optional<TypeExpression*> base_constexpr_type_expression =
        std::nullopt;
    if (base_type_expression) {
      base_constexpr_type_expression = AddConstexpr(*base_type_expression);
    }
    result.push_back(MakeNode<AbstractTypeDeclaration>(
        constexpr_type_identifier, AbstractTypeFlag::kConstexpr,
        base_constexpr_type_expression, constexpr_generates));

    TypeExpression* type_expr = nullptr;
    Identifier* fromconstexpr_identifier = nullptr;
    Identifier* fromconstexpr_parameter_identifier = nullptr;
    Statement* fromconstexpr_body = nullptr;
    if (generate_nonconstexpr) {
      DCHECK(base_type_expression.has_value());
      type_expr = MakeNode<BasicTypeExpression>(std::vector<std::string>{},
                                                MakeNode<Identifier>(name),
                                                std::vector<TypeExpression*>{});

      // return %RawDownCast<Enum>(%FromConstexpr<Base>(o)))
      fromconstexpr_identifier = MakeNode<Identifier>("FromConstexpr");
      fromconstexpr_parameter_identifier = MakeNode<Identifier>("o");
      fromconstexpr_body =
          MakeNode<ReturnStatement>(MakeNode<IntrinsicCallExpression>(
              MakeNode<Identifier>("%RawDownCast"),
              std::vector<TypeExpression*>{type_expr},
              std::vector<Expression*>{MakeNode<IntrinsicCallExpression>(
                  MakeNode<Identifier>("%FromConstexpr"),
                  std::vector<TypeExpression*>{*base_type_expression},
                  std::vector<Expression*>{MakeNode<IdentifierExpression>(
                      std::vector<std::string>{},
                      fromconstexpr_parameter_identifier)})}));
    }

    EnumDescription enum_description{CurrentSourcePosition::Get(), name,
                                     constexpr_generates, is_open};
    std::vector<Declaration*> entry_decls;
    for (const auto& entry : entries) {
      const std::string entry_name = entry.name->value;
      const std::string entry_constexpr_type =
          CONSTEXPR_TYPE_PREFIX + entry_name;
      std::string alias_entry;
      if (entry.alias_entry) {
        alias_entry = constexpr_generates + "::" + *entry.alias_entry;
      }
      enum_description.entries.emplace_back(
          constexpr_generates + "::" + entry_name, alias_entry);

      entry_decls.push_back(MakeNode<AbstractTypeDeclaration>(
          MakeNode<Identifier>(entry_constexpr_type),
          AbstractTypeFlag::kConstexpr, constexpr_type_expression,
          constexpr_generates));

      bool generate_typed_constant = entry.type.has_value();
      if (generate_typed_constant) {
        // namespace Enum {
        //   const constexpr_constant_kEntry0: constexpr kEntry0 constexpr
        //   'Enum::kEntry0'; const kEntry0 = %RawDownCast<T,
        //   Base>(FromConstexpr<Enum>(constexpr_constant_kEntry0));
        // }
        if (!generate_nonconstexpr) {
          Error(
              "Enum constants with custom types require an enum with an "
              "extends clause.")
              .Position((*entry.type)->pos);
        }
        Identifier* constexpr_constant_name =
            MakeNode<Identifier>("constexpr constant " + entry_name);
        entry_decls.push_back(MakeNode<ExternConstDeclaration>(
            constexpr_constant_name,
            MakeNode<BasicTypeExpression>(
                std::vector<std::string>{},
                MakeNode<Identifier>(entry_constexpr_type),
                std::vector<TypeExpression*>{}),
            constexpr_generates + "::" + entry_name));
        entry_decls.push_back(MakeNode<ConstDeclaration>(
            entry.name, *entry.type,
            MakeNode<IntrinsicCallExpression>(
                MakeNode<Identifier>("%RawDownCast"),
                std::vector<TypeExpression*>{*entry.type,
                                             *base_type_expression},
                std::vector<Expression*>{MakeCall(
                    MakeNode<Identifier>("FromConstexpr"), {type_expr},
                    {MakeNode<IdentifierExpression>(std::vector<std::string>{},
                                                    constexpr_constant_name)},
                    {})})));
      } else {
        // namespace Enum {
        //   const kEntry0: constexpr kEntry0 constexpr 'Enum::kEntry0';
        // }
        entry_decls.push_back(MakeNode<ExternConstDeclaration>(
            entry.name,
            MakeNode<BasicTypeExpression>(
                std::vector<std::string>{},
                MakeNode<Identifier>(entry_constexpr_type),
                std::vector<TypeExpression*>{}),
            constexpr_generates + "::" + entry_name));
      }

      // FromConstexpr<Enum, Enum::constexpr kEntry0>(
      //   : Enum::constexpr kEntry0): Enum
      if (generate_nonconstexpr) {
        TypeExpression* entry_constexpr_type_expr =
            MakeNode<BasicTypeExpression>(
                std::vector<std::string>{name},
                MakeNode<Identifier>(entry_constexpr_type),
                std::vector<TypeExpression*>{});

        ParameterList parameters;
        parameters.names.push_back(fromconstexpr_parameter_identifier);
        parameters.types.push_back(entry_constexpr_type_expr);
        result.push_back(MakeNode<SpecializationDeclaration>(
            false, fromconstexpr_identifier,
            std::vector<TypeExpression*>{type_expr, entry_constexpr_type_expr},
            std::move(parameters), type_expr, LabelAndTypesVector{},
            fromconstexpr_body));
      }
    }

    result.push_back(
        MakeNode<NamespaceDeclaration>(name, std::move(entry_decls)));
    CurrentAst::Get().AddEnumDescription(std::move(enum_description));
  }

  return ParseResult{std::move(result)};
}

std::optional<ParseResult> MakeTypeswitchStatement(
    ParseResultIterator* child_results) {
  auto expression = child_results->NextAs<Expression*>();
  auto cases = child_results->NextAs<std::vector<
"""


```