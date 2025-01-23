Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/torque/implementation-visitor.cc`.

Here's a plan to address the request:

1. **Identify the core purpose:** The code is part of a visitor pattern implementation for processing Torque AST nodes. Specifically, it handles expressions and statements.
2. **Analyze each `Visit` method:**  Each `Visit` function corresponds to a specific node type in the Torque Abstract Syntax Tree (AST). I need to understand the logic within each function.
3. **Relate to JavaScript (if applicable):**  If a Torque construct has a direct parallel in JavaScript, provide an example.
4. **Illustrate code logic:** For complex logic (like conditional or logical expressions), provide example inputs and outputs to show how the code behaves.
5. **Highlight potential errors:** Identify common programming mistakes that might surface when using the corresponding Torque constructs.
6. **Summarize overall functionality:**  Condense the individual functionalities into a concise summary.
这是 `v8/src/torque/implementation-visitor.cc` 的第 2 部分代码，主要负责实现 Torque 语法中各种表达式和语句的访问和代码生成逻辑。它延续了第 1 部分的功能，将 Torque 代码转换为底层的指令。

以下是该部分代码功能的归纳：

**核心功能：实现 Torque 表达式和语句的访问和代码生成**

这部分代码定义了 `ImplementationVisitor` 类的多个 `Visit` 方法，每个方法对应处理一种特定的 Torque 表达式或语句。这些方法的主要任务是：

* **类型检查和转换:**  确保操作数类型符合预期，并在必要时进行隐式类型转换。
* **生成中间代码:**  将 Torque 语法结构转换为 V8 汇编器能够理解的指令。这通常涉及到创建新的代码块 (Blocks) 和发出 (Emit) 指令。
* **处理控制流:**  实现条件语句 (`if`)、循环语句 (`while`) 和跳转语句 (`goto`) 的逻辑控制。
* **处理字面量:**  生成常量字面量（例如，整数、浮点数、字符串）的表示。
* **处理变量和字段访问:**  生成访问局部变量和对象字段的代码。
* **处理操作符:**  实现各种操作符（例如，算术、逻辑、赋值）的语义。
* **处理内置函数调用:**  生成调用内置函数的代码。
* **处理断言:**  生成用于运行时或静态代码检查的断言。
* **处理返回值:**  生成函数返回语句的代码。
* **处理标签和异常处理:**  实现 `try-label` 语句块的逻辑。
* **处理类初始化:**  生成用于创建和初始化类实例的代码。

**更细致的功能点:**

* **`Visit(ConditionalExpression* expr)`:** 处理条件表达式（三元运算符 `? :`）。它会为 `true` 和 `false` 分支创建代码块，确保两个分支的结果可以转换为相同的类型。

   **JavaScript 示例:**  Torque 中的条件表达式类似于 JavaScript 的三元运算符。例如，Torque 代码 `x ? a : b` 类似于 JavaScript 的 `x ? a : b`。

   **代码逻辑推理:** 假设输入 `expr->condition` 的值为 `true`，那么会执行 `true_block` 中的代码，计算 `expr->if_true` 的值。如果 `expr->condition` 的值为 `false`，那么会执行 `false_block` 中的代码，计算 `expr->if_false` 的值。最终会选择其中一个分支的结果。

* **`Visit(LogicalOrExpression* expr)` 和 `Visit(LogicalAndExpression* expr)`:** 处理逻辑或 (`||`) 和逻辑与 (`&&`) 表达式。它们实现了短路求值的语义。

   **JavaScript 示例:** Torque 的逻辑运算符与 JavaScript 的行为一致。例如，`a || b` 在 JavaScript 中，如果 `a` 为真，则不会计算 `b`。

   **代码逻辑推理 (LogicalOrExpression):** 如果 `expr->left` 的结果为真，则直接跳转到 `true_block`，返回 `true`，不再计算 `expr->right`。如果 `expr->left` 的结果为假，则跳转到 `false_block`，计算 `expr->right` 的值并返回。

* **`Visit(IncrementDecrementExpression* expr)`:** 处理自增 (`++`) 和自减 (`--`) 运算符。它会根据前缀或后缀形式返回原始值或更新后的值。

   **JavaScript 示例:** Torque 的自增自减运算符与 JavaScript 的行为一致。`++i` (前缀) 先自增再返回，`i++` (后缀) 先返回再自增。

   **假设输入与输出:** 假设变量 `x` 的值为 `5`。如果表达式是 `++x`，输出将是 `6`，并且 `x` 的值会更新为 `6`。如果表达式是 `x++`，输出将是 `5`，但执行后 `x` 的值会更新为 `6`。

* **`Visit(AssignmentExpression* expr)`:** 处理赋值表达式。

   **JavaScript 示例:**  Torque 的赋值运算符与 JavaScript 类似，例如 `x = y`。

* **`Visit(FloatingPointLiteralExpression* expr)` 和 `Visit(IntegerLiteralExpression* expr)`:** 处理浮点数和整数类型的字面量。

* **`Visit(AssumeTypeImpossibleExpression* expr)`:**  表示一个类型断言，断言某个表达式不可能具有特定的类型。如果该断言不成立，则会报错。

* **`Visit(StringLiteralExpression* expr)`:** 处理字符串字面量。

* **`Visit(LocationExpression* expr)` 和 `Visit(FieldAccessExpression* expr)`:**  用于获取变量或对象字段的值。

* **`Visit(GotoStatement* stmt)`:** 处理跳转到标签语句。

* **`Visit(IfStatement* stmt)`:** 处理条件语句。它可以处理编译时常量条件 (`is_constexpr`) 和运行时条件。

   **用户常见的编程错误:**  在 `constexpr if` 语句中，如果 `true` 和 `false` 分支的返回行为不一致（一个返回 `never`，另一个不返回），会导致编译错误。

* **`Visit(WhileStatement* stmt)`:** 处理循环语句。

* **`Visit(BlockStatement* block)`:** 处理代码块，它会管理代码块内的局部变量作用域。

* **`Visit(DebugStatement* stmt)`:** 处理调试语句，例如 `unreachable` 和 `debug break`。

* **`Visit(AssertStatement* stmt)`:** 处理断言语句，用于在运行时或编译时检查条件是否为真。

* **`Visit(ExpressionStatement* stmt)`:**  处理只包含表达式的语句。

* **`Visit(ReturnStatement* stmt)`:** 处理函数返回语句。

   **用户常见的编程错误:**  如果函数声明了返回值类型，但在 `return` 语句中没有提供返回值，或者返回值的类型与声明的类型不匹配，则会导致编译错误。同样，如果函数声明为 `void` 或 `never` 返回类型，却尝试在 `return` 语句中返回值，也会导致错误。

* **`Visit(TryLabelExpression* expr)`:** 处理 `try-label` 语句，这是一种 Torque 特有的异常处理机制。

* **`Visit(StatementExpression* expr)`:** 处理可以作为表达式使用的语句（例如，包含赋值的语句）。

* **`VisitInitializerResults`，`GenerateFieldReference`，`InitializeClass` 等方法:**  这些方法涉及到类实例的初始化，包括分配内存、计算字段偏移量、调用初始化器等。

总而言之，这部分代码是 Torque 编译器中至关重要的一部分，它负责将高级的 Torque 语法转换为可以在 V8 虚拟机中执行的低级指令，并且在转换过程中进行类型检查和错误报告，确保生成的代码的正确性。

### 提示词
```
这是目录为v8/src/torque/implementation-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/implementation-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
itResult ImplementationVisitor::Visit(ConditionalExpression* expr) {
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
```