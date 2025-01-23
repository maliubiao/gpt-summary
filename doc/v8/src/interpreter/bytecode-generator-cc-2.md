Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `bytecode-generator.cc`. The summary should also address specific points:

1. **General Functionality:** Describe what the code does.
2. **Torque Source:** Check if the filename ends with `.tq` and state if it's Torque code.
3. **JavaScript Relation:** If it's related to JavaScript functionality, provide a JavaScript example.
4. **Code Logic Inference:** If there's code logic, provide example input and output.
5. **Common Programming Errors:** Mention common programming errors this code might relate to.
6. **Part Number:** Acknowledge this is part 3 of 11.

Let's break down the provided code snippet:

*   **Generator Handling:** The initial comments and the `GenerateGeneratorBody` function clearly relate to the generation of bytecode for generator functions (both regular and async). It handles try-finally and try-catch blocks within the generator's execution.
*   **Statement Generation:**  Functions like `GenerateBodyStatements`, `GenerateBodyStatementsWithoutImplicitFinalReturn`, `VisitBlock`, `VisitStatements`, etc., are responsible for generating bytecode for different JavaScript statements.
*   **Declaration Handling:** Functions like `VisitVariableDeclaration`, `VisitFunctionDeclaration`, `VisitModuleNamespaceImports`, and `VisitDeclarations` deal with generating bytecode for declarations.
*   **Control Flow:**  The code includes logic for `if`, `continue`, `break`, `return`, `with`, and `switch` statements. The `VisitSwitchStatement` function has a section on optimizing switch statements using jump tables.
*   **Try-Catch and Try-Finally:** The `BuildTryCatch` and `BuildTryFinally` functions handle the generation of bytecode for exception handling.

Based on this analysis, I can now formulate the summary and address the specific points.
这是 `v8/src/interpreter/bytecode-generator.cc` 源代码的第三部分，主要负责生成函数体内部的字节码，特别是针对生成器函数和异常处理的场景。

**功能归纳:**

这部分代码的主要功能是为 JavaScript 函数（特别是生成器函数）生成字节码。它处理了函数体内的各种语句，包括声明、控制流语句（如 `if`、`switch`、`return`、`break`、`continue`）以及异常处理结构（`try-catch` 和 `try-finally`）。对于生成器函数，它负责生成启动、恢复和关闭生成器的字节码，并处理异步生成器的特殊情况。

**其他要点:**

*   **.tq 检查:**  `v8/src/interpreter/bytecode-generator.cc` 的文件名以 `.cc` 结尾，而不是 `.tq`。因此，它不是 v8 Torque 源代码，而是标准的 C++ 源代码。
*   **JavaScript 功能关系及举例:** 这部分代码直接关系到 JavaScript 中函数（特别是生成器函数）的执行。它将 JavaScript 代码转换为 V8 虚拟机可以执行的字节码。

    **JavaScript 示例 (生成器函数):**

    ```javascript
    function* myGenerator() {
      console.log('开始执行');
      yield 1;
      try {
        yield 2;
        return 3;
      } finally {
        console.log('清理操作');
      }
      yield 4;
    }

    const generator = myGenerator();
    console.log(generator.next()); // 输出: 开始执行, { value: 1, done: false }
    console.log(generator.next()); // 输出: { value: 2, done: false }
    console.log(generator.next()); // 输出: 清理操作, { value: 3, done: true }
    console.log(generator.next()); // 输出: { value: undefined, done: true }
    ```

    `bytecode-generator.cc` 中的代码，特别是 `GenerateGeneratorBody` 函数及其调用的其他函数，负责将类似 `myGenerator` 这样的 JavaScript 代码转换成 V8 能够理解和执行的字节码指令。 例如，`BuildTryFinally` 函数会处理 `finally` 块的逻辑，确保无论 `try` 块是否抛出异常或执行 `return`，`finally` 块中的代码都会被执行。

*   **代码逻辑推理 (Switch 语句优化):**  `VisitSwitchStatement` 函数中有一个有趣的优化逻辑，它尝试将 `switch` 语句转换为跳转表以提高性能，特别是当 `case` 的值是小的整数（Smi）时。

    **假设输入 (JavaScript Switch 语句):**

    ```javascript
    function testSwitch(x) {
      let result = '';
      switch (x) {
        case 1:
          result = 'one';
          break;
        case 2:
          result = 'two';
          break;
        case 5:
          result = 'five';
          break;
        default:
          result = 'other';
      }
      return result;
    }
    ```

    **输出 (推测的字节码指令 - 简化表示):**

    假设满足跳转表优化的条件（例如，`case` 的值是 Smi 且分布相对集中），`VisitSwitchStatement` 可能会生成类似以下的字节码指令：

    1. 加载 `x` 的值到寄存器。
    2. 检查 `x` 的类型是否为数字。
    3. 检查 `x` 是否在 Smi 的范围内。
    4. 将 `x` 转换为 Smi（如果需要）。
    5. 使用 `switch_on_smi` 指令，根据 `x` 的值跳转到相应的 `case` 标签。
    6. 如果 `x` 的值不在跳转表中，则跳转到 `default` 标签（或者一系列的比较跳转指令）。
    7. 每个 `case` 标签的代码。
    8. `default` 标签的代码。

*   **用户常见的编程错误 (Try-Catch):**  `BuildTryCatch` 函数处理异常捕获。一个常见的编程错误是**没有正确处理捕获的异常**，或者**捕获了过于宽泛的异常类型**，导致本不应该被捕获的错误也被捕获，隐藏了潜在的问题。

    **JavaScript 示例 (错误的异常处理):**

    ```javascript
    function riskyOperation(input) {
      if (input < 0) {
        throw new Error("Input cannot be negative");
      }
      // ... 其他可能出错的操作
    }

    function processInput(input) {
      try {
        riskyOperation(input);
        // ... 正常处理逻辑
      } catch (error) {
        console.error("Something went wrong:", error); // 仅仅打印错误，没有做进一步处理
        // 更好的做法可能是根据错误类型进行不同的处理，或者重新抛出异常
      }
    }

    processInput(-5); // 输出: Something went wrong: Error: Input cannot be negative
    ```

    在这个例子中，虽然捕获了异常，但只是简单地打印出来，没有根据具体的错误类型采取相应的恢复或处理措施。 `BuildTryCatch` 生成的字节码确保了当 `try` 块中抛出异常时，控制流会跳转到 `catch` 块，但如何处理异常取决于程序员在 `catch` 块中的代码。

总而言之，这部分 `bytecode-generator.cc` 代码是 V8 解释器中至关重要的一部分，它负责将高级的 JavaScript 代码转换为底层的字节码指令，使得 V8 虚拟机能够高效地执行 JavaScript 代码，尤其是在处理复杂的控制流和异常情况时。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
lose(generator);
  // }
  //
  // - InitialYield yields the actual generator object.
  // - Any return statement inside the body will have its argument wrapped
  //   in an iterator result object with a "done" property set to `true`.
  // - If the generator terminates for whatever reason, we must close it.
  //   Hence the finally clause.
  // - BytecodeGenerator performs special handling for ReturnStatements in
  //   async generator functions, resolving the appropriate Promise with an
  //   "done" iterator result object containing a Promise-unwrapped value.

  // In async generator functions, when parameters are not simple,
  // a parameter initialization block will be added as the first block to the
  // AST. Since this block can throw synchronously, it should not be wrapped
  // in the following try-finally. We visit this block outside the try-finally
  // and remove it from the AST.
  int start = 0;
  ZonePtrList<Statement>* statements = info()->literal()->body();
  Statement* stmt = statements->at(0);
  if (stmt->IsBlock()) {
    Block* block = static_cast<Block*>(statements->at(0));
    if (block->is_initialization_block_for_parameters()) {
      VisitBlockDeclarationsAndStatements(block);
      start = 1;
    }
  }

  BuildTryFinally(
      [&]() {
        BuildTryCatch(
            [&]() { GenerateBodyStatements(start); },
            [&](Register context) {
              RegisterAllocationScope register_scope(this);
              RegisterList args = register_allocator()->NewRegisterList(2);
              builder()
                  ->MoveRegister(generator_object(), args[0])
                  .StoreAccumulatorInRegister(args[1])  // exception
                  .CallRuntime(Runtime::kInlineAsyncGeneratorReject, args);
              execution_control()->ReturnAccumulator(kNoSourcePosition);
            },
            catch_prediction());
      },
      [&](Register body_continuation_token, Register body_continuation_result) {
        RegisterAllocationScope register_scope(this);
        Register arg = register_allocator()->NewRegister();
        builder()
            ->MoveRegister(generator_object(), arg)
            .CallRuntime(Runtime::kInlineGeneratorClose, arg);
      },
      catch_prediction());
}

void BytecodeGenerator::GenerateBodyStatements(int start) {
  GenerateBodyStatementsWithoutImplicitFinalReturn(start);

  // Emit an implicit return instruction in case control flow can fall off the
  // end of the function without an explicit return being present on all paths.
  //
  // ControlScope is used instead of building the Return bytecode directly, as
  // the entire body is wrapped in a try-finally block for async generators.
  if (!builder()->RemainderOfBlockIsDead()) {
    builder()->LoadUndefined();
    const int pos = info()->literal()->return_position();
    if (IsAsyncFunction(function_kind()) ||
        IsModuleWithTopLevelAwait(function_kind())) {
      execution_control()->AsyncReturnAccumulator(pos);
    } else {
      execution_control()->ReturnAccumulator(pos);
    }
  }
}

void BytecodeGenerator::GenerateBodyStatementsWithoutImplicitFinalReturn(
    int start) {
  ZonePtrList<Statement>* body = info()->literal()->body();
  if (v8_flags.js_explicit_resource_management && closure_scope() != nullptr &&
      (closure_scope()->has_using_declaration() ||
       closure_scope()->has_await_using_declaration())) {
    BuildDisposeScope([&]() { VisitStatements(body, start); },
                      closure_scope()->has_await_using_declaration());
  } else {
    VisitStatements(body, start);
  }
}

void BytecodeGenerator::AllocateTopLevelRegisters() {
  if (IsResumableFunction(info()->literal()->kind())) {
    // Either directly use generator_object_var or allocate a new register for
    // the incoming generator object.
    Variable* generator_object_var = closure_scope()->generator_object_var();
    if (generator_object_var->location() == VariableLocation::LOCAL) {
      incoming_new_target_or_generator_ =
          GetRegisterForLocalVariable(generator_object_var);
    } else {
      incoming_new_target_or_generator_ = register_allocator()->NewRegister();
    }
  } else if (closure_scope()->new_target_var()) {
    // Either directly use new_target_var or allocate a new register for
    // the incoming new target object.
    Variable* new_target_var = closure_scope()->new_target_var();
    if (new_target_var->location() == VariableLocation::LOCAL) {
      incoming_new_target_or_generator_ =
          GetRegisterForLocalVariable(new_target_var);
    } else {
      incoming_new_target_or_generator_ = register_allocator()->NewRegister();
    }
  }
}

void BytecodeGenerator::BuildGeneratorPrologue() {
  DCHECK_GT(info()->literal()->suspend_count(), 0);
  DCHECK(generator_object().is_valid());
  generator_jump_table_ =
      builder()->AllocateJumpTable(info()->literal()->suspend_count(), 0);

  // If the generator is not undefined, this is a resume, so perform state
  // dispatch.
  builder()->SwitchOnGeneratorState(generator_object(), generator_jump_table_);

  // Otherwise, fall-through to the ordinary function prologue, after which we
  // will run into the generator object creation and other extra code inserted
  // by the parser.
}

void BytecodeGenerator::VisitBlock(Block* stmt) {
  // Visit declarations and statements.
  CurrentScope current_scope(this, stmt->scope());
  if (stmt->scope() != nullptr && stmt->scope()->NeedsContext()) {
    BuildNewLocalBlockContext(stmt->scope());
    ContextScope scope(this, stmt->scope());
    VisitBlockMaybeDispose(stmt);
  } else {
    VisitBlockMaybeDispose(stmt);
  }
}

void BytecodeGenerator::VisitBlockMaybeDispose(Block* stmt) {
  if (v8_flags.js_explicit_resource_management && stmt->scope() != nullptr &&
      (stmt->scope()->has_using_declaration() ||
       stmt->scope()->has_await_using_declaration())) {
    BuildDisposeScope([&]() { VisitBlockDeclarationsAndStatements(stmt); },
                      stmt->scope()->has_await_using_declaration());
  } else {
    VisitBlockDeclarationsAndStatements(stmt);
  }
}

void BytecodeGenerator::VisitBlockDeclarationsAndStatements(Block* stmt) {
  BlockBuilder block_builder(builder(), block_coverage_builder_, stmt);
  ControlScopeForBreakable execution_control(this, stmt, &block_builder);
  if (stmt->scope() != nullptr) {
    VisitDeclarations(stmt->scope()->declarations());
  }
  if (V8_UNLIKELY(stmt->is_breakable())) {
    // Loathsome labeled blocks can be the target of break statements, which
    // causes unconditional blocks to act conditionally, and therefore to
    // require their own elision scope.
    //
    // lbl: {
    //   if (cond) break lbl;
    //   x;
    // }
    // x;  <-- Cannot elide TDZ check
    HoleCheckElisionScope elider(this);
    VisitStatements(stmt->statements());
  } else {
    VisitStatements(stmt->statements());
  }
}

void BytecodeGenerator::VisitVariableDeclaration(VariableDeclaration* decl) {
  Variable* variable = decl->var();
  // Unused variables don't need to be visited.
  if (!variable->is_used()) return;

  switch (variable->location()) {
    case VariableLocation::UNALLOCATED:
    case VariableLocation::MODULE:
      UNREACHABLE();
    case VariableLocation::LOCAL:
      if (variable->binding_needs_init()) {
        Register destination(builder()->Local(variable->index()));
        builder()->LoadTheHole().StoreAccumulatorInRegister(destination);
      }
      break;
    case VariableLocation::PARAMETER:
      if (variable->binding_needs_init()) {
        Register destination(builder()->Parameter(variable->index()));
        builder()->LoadTheHole().StoreAccumulatorInRegister(destination);
      }
      break;
    case VariableLocation::REPL_GLOBAL:
      // REPL let's are stored in script contexts. They get initialized
      // with the hole the same way as normal context allocated variables.
    case VariableLocation::CONTEXT:
      if (variable->binding_needs_init()) {
        DCHECK_EQ(0, execution_context()->ContextChainDepth(variable->scope()));
        builder()->LoadTheHole().StoreContextSlot(execution_context()->reg(),
                                                  variable, 0);
      }
      break;
    case VariableLocation::LOOKUP: {
      DCHECK_EQ(VariableMode::kDynamic, variable->mode());
      DCHECK(!variable->binding_needs_init());

      Register name = register_allocator()->NewRegister();

      builder()
          ->LoadLiteral(variable->raw_name())
          .StoreAccumulatorInRegister(name)
          .CallRuntime(Runtime::kDeclareEvalVar, name);
      break;
    }
  }
}

void BytecodeGenerator::VisitFunctionDeclaration(FunctionDeclaration* decl) {
  Variable* variable = decl->var();
  DCHECK(variable->mode() == VariableMode::kLet ||
         variable->mode() == VariableMode::kVar ||
         variable->mode() == VariableMode::kDynamic);
  // Unused variables don't need to be visited.
  if (!variable->is_used()) return;

  switch (variable->location()) {
    case VariableLocation::UNALLOCATED:
    case VariableLocation::MODULE:
      UNREACHABLE();
    case VariableLocation::PARAMETER:
    case VariableLocation::LOCAL: {
      VisitFunctionLiteral(decl->fun());
      BuildVariableAssignment(variable, Token::kInit, HoleCheckMode::kElided);
      break;
    }
    case VariableLocation::REPL_GLOBAL:
    case VariableLocation::CONTEXT: {
      DCHECK_EQ(0, execution_context()->ContextChainDepth(variable->scope()));
      VisitFunctionLiteral(decl->fun());
      builder()->StoreContextSlot(execution_context()->reg(), variable, 0);
      break;
    }
    case VariableLocation::LOOKUP: {
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->LoadLiteral(variable->raw_name())
          .StoreAccumulatorInRegister(args[0]);
      VisitFunctionLiteral(decl->fun());
      builder()->StoreAccumulatorInRegister(args[1]).CallRuntime(
          Runtime::kDeclareEvalFunction, args);
      break;
    }
  }
  DCHECK_IMPLIES(
      eager_inner_literals_ != nullptr && decl->fun()->ShouldEagerCompile(),
      IsInEagerLiterals(decl->fun(), *eager_inner_literals_));
}

void BytecodeGenerator::VisitModuleNamespaceImports() {
  if (!closure_scope()->is_module_scope()) return;

  RegisterAllocationScope register_scope(this);
  Register module_request = register_allocator()->NewRegister();

  SourceTextModuleDescriptor* descriptor =
      closure_scope()->AsModuleScope()->module();
  for (auto entry : descriptor->namespace_imports()) {
    builder()
        ->LoadLiteral(Smi::FromInt(entry->module_request))
        .StoreAccumulatorInRegister(module_request)
        .CallRuntime(Runtime::kGetModuleNamespace, module_request);
    Variable* var = closure_scope()->LookupInModule(entry->local_name);
    BuildVariableAssignment(var, Token::kInit, HoleCheckMode::kElided);
  }
}

void BytecodeGenerator::BuildDeclareCall(Runtime::FunctionId id) {
  if (!top_level_builder()->has_top_level_declaration()) return;
  DCHECK(!top_level_builder()->processed());

  top_level_builder()->set_constant_pool_entry(
      builder()->AllocateDeferredConstantPoolEntry());

  // Emit code to declare globals.
  RegisterList args = register_allocator()->NewRegisterList(2);
  builder()
      ->LoadConstantPoolEntry(top_level_builder()->constant_pool_entry())
      .StoreAccumulatorInRegister(args[0])
      .MoveRegister(Register::function_closure(), args[1])
      .CallRuntime(id, args);

  top_level_builder()->mark_processed();
}

void BytecodeGenerator::VisitModuleDeclarations(Declaration::List* decls) {
  RegisterAllocationScope register_scope(this);
  for (Declaration* decl : *decls) {
    Variable* var = decl->var();
    if (!var->is_used()) continue;
    if (var->location() == VariableLocation::MODULE) {
      if (decl->IsFunctionDeclaration()) {
        DCHECK(var->IsExport());
        FunctionDeclaration* f = static_cast<FunctionDeclaration*>(decl);
        AddToEagerLiteralsIfEager(f->fun());
        top_level_builder()->record_module_function_declaration();
      } else if (var->IsExport() && var->binding_needs_init()) {
        DCHECK(decl->IsVariableDeclaration());
        top_level_builder()->record_module_variable_declaration();
      }
    } else {
      RegisterAllocationScope inner_register_scope(this);
      Visit(decl);
    }
  }
  BuildDeclareCall(Runtime::kDeclareModuleExports);
}

void BytecodeGenerator::VisitGlobalDeclarations(Declaration::List* decls) {
  RegisterAllocationScope register_scope(this);
  for (Declaration* decl : *decls) {
    Variable* var = decl->var();
    DCHECK(var->is_used());
    if (var->location() == VariableLocation::UNALLOCATED) {
      // var or function.
      if (decl->IsFunctionDeclaration()) {
        top_level_builder()->record_global_function_declaration();
        FunctionDeclaration* f = static_cast<FunctionDeclaration*>(decl);
        AddToEagerLiteralsIfEager(f->fun());
      } else {
        top_level_builder()->record_global_variable_declaration();
      }
    } else {
      // let or const. Handled in NewScriptContext.
      DCHECK(decl->IsVariableDeclaration());
      DCHECK(IsLexicalVariableMode(var->mode()));
    }
  }

  BuildDeclareCall(Runtime::kDeclareGlobals);
}

void BytecodeGenerator::VisitDeclarations(Declaration::List* declarations) {
  for (Declaration* decl : *declarations) {
    RegisterAllocationScope register_scope(this);
    Visit(decl);
  }
}

void BytecodeGenerator::VisitStatements(
    const ZonePtrList<Statement>* statements, int start) {
  for (int i = start; i < statements->length(); i++) {
    // Allocate an outer register allocations scope for the statement.
    RegisterAllocationScope allocation_scope(this);
    Statement* stmt = statements->at(i);
    Visit(stmt);
    if (builder()->RemainderOfBlockIsDead()) break;
  }
}

void BytecodeGenerator::VisitExpressionStatement(ExpressionStatement* stmt) {
  builder()->SetStatementPosition(stmt);
  VisitForEffect(stmt->expression());
}

void BytecodeGenerator::VisitEmptyStatement(EmptyStatement* stmt) {}

void BytecodeGenerator::VisitIfStatement(IfStatement* stmt) {
  ConditionalControlFlowBuilder conditional_builder(
      builder(), block_coverage_builder_, stmt);
  builder()->SetStatementPosition(stmt);

  if (stmt->condition()->ToBooleanIsTrue()) {
    // Generate then block unconditionally as always true.
    conditional_builder.Then();
    Visit(stmt->then_statement());
  } else if (stmt->condition()->ToBooleanIsFalse()) {
    // Generate else block unconditionally if it exists.
    if (stmt->HasElseStatement()) {
      conditional_builder.Else();
      Visit(stmt->else_statement());
    }
  } else {
    // TODO(oth): If then statement is BreakStatement or
    // ContinueStatement we can reduce number of generated
    // jump/jump_ifs here. See BasicLoops test.
    VisitForTest(stmt->condition(), conditional_builder.then_labels(),
                 conditional_builder.else_labels(), TestFallthrough::kThen);

    HoleCheckElisionMergeScope merge_elider(this);
    {
      HoleCheckElisionMergeScope::Branch branch(merge_elider);
      conditional_builder.Then();
      Visit(stmt->then_statement());
    }

    {
      HoleCheckElisionMergeScope::Branch branch(merge_elider);
      if (stmt->HasElseStatement()) {
        conditional_builder.JumpToEnd();
        conditional_builder.Else();
        Visit(stmt->else_statement());
      }
    }

    merge_elider.Merge();
  }
}

void BytecodeGenerator::VisitSloppyBlockFunctionStatement(
    SloppyBlockFunctionStatement* stmt) {
  Visit(stmt->statement());
}

void BytecodeGenerator::VisitContinueStatement(ContinueStatement* stmt) {
  AllocateBlockCoverageSlotIfEnabled(stmt, SourceRangeKind::kContinuation);
  builder()->SetStatementPosition(stmt);
  execution_control()->Continue(stmt->target());
}

void BytecodeGenerator::VisitBreakStatement(BreakStatement* stmt) {
  AllocateBlockCoverageSlotIfEnabled(stmt, SourceRangeKind::kContinuation);
  builder()->SetStatementPosition(stmt);
  execution_control()->Break(stmt->target());
}

void BytecodeGenerator::VisitReturnStatement(ReturnStatement* stmt) {
  AllocateBlockCoverageSlotIfEnabled(stmt, SourceRangeKind::kContinuation);
  builder()->SetStatementPosition(stmt);
  VisitForAccumulatorValue(stmt->expression());
  int return_position = stmt->end_position();
  if (return_position == ReturnStatement::kFunctionLiteralReturnPosition) {
    return_position = info()->literal()->return_position();
  }
  if (stmt->is_async_return()) {
    execution_control()->AsyncReturnAccumulator(return_position);
  } else {
    execution_control()->ReturnAccumulator(return_position);
  }
}

void BytecodeGenerator::VisitWithStatement(WithStatement* stmt) {
  builder()->SetStatementPosition(stmt);
  VisitForAccumulatorValue(stmt->expression());
  BuildNewLocalWithContext(stmt->scope());
  VisitInScope(stmt->statement(), stmt->scope());
}

namespace {

bool IsSmiLiteralSwitchCaseValue(Expression* expr) {
  if (expr->IsSmiLiteral() ||
      (expr->IsLiteral() && expr->AsLiteral()->IsNumber() &&
       expr->AsLiteral()->AsNumber() == 0.0)) {
    return true;
#ifdef DEBUG
  } else if (expr->IsLiteral() && expr->AsLiteral()->IsNumber()) {
    DCHECK(!IsSmiDouble(expr->AsLiteral()->AsNumber()));
#endif
  }
  return false;
}

// Precondition: we called IsSmiLiteral to check this.
inline int ReduceToSmiSwitchCaseValue(Expression* expr) {
  if (V8_LIKELY(expr->IsSmiLiteral())) {
    return expr->AsLiteral()->AsSmiLiteral().value();
  } else {
    // Only the zero case is possible otherwise.
    DCHECK(expr->IsLiteral() && expr->AsLiteral()->IsNumber() &&
           expr->AsLiteral()->AsNumber() == -0.0);
    return 0;
  }
}

// Is the range of Smi's small enough relative to number of cases?
inline bool IsSpreadAcceptable(int spread, int ncases) {
  return spread < v8_flags.switch_table_spread_threshold * ncases;
}

struct SwitchInfo {
  static const int kDefaultNotFound = -1;

  std::map<int, CaseClause*> covered_cases;
  int default_case;

  SwitchInfo() { default_case = kDefaultNotFound; }

  bool DefaultExists() { return default_case != kDefaultNotFound; }
  bool CaseExists(int j) {
    return covered_cases.find(j) != covered_cases.end();
  }
  bool CaseExists(Expression* expr) {
    return IsSmiLiteralSwitchCaseValue(expr)
               ? CaseExists(ReduceToSmiSwitchCaseValue(expr))
               : false;
  }
  CaseClause* GetClause(int j) { return covered_cases[j]; }

  bool IsDuplicate(CaseClause* clause) {
    return IsSmiLiteralSwitchCaseValue(clause->label()) &&
           CaseExists(clause->label()) &&
           clause != GetClause(ReduceToSmiSwitchCaseValue(clause->label()));
  }
  int MinCase() {
    return covered_cases.empty() ? INT_MAX : covered_cases.begin()->first;
  }
  int MaxCase() {
    return covered_cases.empty() ? INT_MIN : covered_cases.rbegin()->first;
  }
  void Print() {
    std::cout << "Covered_cases: " << '\n';
    for (auto iter = covered_cases.begin(); iter != covered_cases.end();
         ++iter) {
      std::cout << iter->first << "->" << iter->second << '\n';
    }
    std::cout << "Default_case: " << default_case << '\n';
  }
};

// Checks whether we should use a jump table to implement a switch operation.
bool IsSwitchOptimizable(SwitchStatement* stmt, SwitchInfo* info) {
  ZonePtrList<CaseClause>* cases = stmt->cases();

  for (int i = 0; i < cases->length(); ++i) {
    CaseClause* clause = cases->at(i);
    if (clause->is_default()) {
      continue;
    } else if (!(clause->label()->IsLiteral())) {
      // Don't consider Smi cases after a non-literal, because we
      // need to evaluate the non-literal.
      break;
    } else if (IsSmiLiteralSwitchCaseValue(clause->label())) {
      int value = ReduceToSmiSwitchCaseValue(clause->label());
      info->covered_cases.insert({value, clause});
    }
  }

  // GCC also jump-table optimizes switch statements with 6 cases or more.
  if (static_cast<int>(info->covered_cases.size()) >=
      v8_flags.switch_table_min_cases) {
    // Due to case spread will be used as the size of jump-table,
    // we need to check if it doesn't overflow by casting its
    // min and max bounds to int64_t, and calculate if the difference is less
    // than or equal to INT_MAX.
    int64_t min = static_cast<int64_t>(info->MinCase());
    int64_t max = static_cast<int64_t>(info->MaxCase());
    int64_t spread = max - min + 1;

    DCHECK_GT(spread, 0);

    // Check if casted spread is acceptable and doesn't overflow.
    if (spread <= INT_MAX &&
        IsSpreadAcceptable(static_cast<int>(spread), cases->length())) {
      return true;
    }
  }
  // Invariant- covered_cases has all cases and only cases that will go in the
  // jump table.
  info->covered_cases.clear();
  return false;
}

}  // namespace

// This adds a jump table optimization for switch statements with Smi cases.
// If there are 5+ non-duplicate Smi clauses, and they are sufficiently compact,
// we generate a jump table. In the fall-through path, we put the compare-jumps
// for the non-Smi cases.

// e.g.
//
// switch(x){
//   case -0: out = 10;
//   case 1: out = 11; break;
//   case 0: out = 12; break;
//   case 2: out = 13;
//   case 3: out = 14; break;
//   case 0.5: out = 15; break;
//   case 4: out = 16;
//   case y: out = 17;
//   case 5: out = 18;
//   default: out = 19; break;
// }

// becomes this pseudo-bytecode:

//   lda x
//   star r1
//   test_type number
//   jump_if_false @fallthrough
//   ldar r1
//   test_greater_than_or_equal_to smi_min
//   jump_if_false @fallthrough
//   ldar r1
//   test_less_than_or_equal_to smi_max
//   jump_if_false @fallthrough
//   ldar r1
//   bitwise_or 0
//   star r2
//   test_strict_equal r1
//   jump_if_false @fallthrough
//   ldar r2
//   switch_on_smi {1: @case_1, 2: @case_2, 3: @case_3, 4: @case_4}
// @fallthrough:
//   jump_if_strict_equal -0.0 @case_minus_0.0
//   jump_if_strict_equal 0.5  @case_0.5
//   jump_if_strict_equal y    @case_y
//   jump_if_strict_equal 5    @case_5
//   jump @default
// @case_minus_0.0:
//   <out = 10>
// @case_1
//   <out = 11, break>
// @case_0:
//   <out = 12, break>
// @case_2:
//   <out = 13>
// @case_3:
//   <out = 14, break>
// @case_0.5:
//   <out = 15, break>
// @case_4:
//   <out = 16>
// @case_y:
//   <out = 17>
// @case_5:
//   <out = 18>
// @default:
//   <out = 19, break>

void BytecodeGenerator::VisitSwitchStatement(SwitchStatement* stmt) {
  // We need this scope because we visit for register values. We have to
  // maintain an execution result scope where registers can be allocated.
  ZonePtrList<CaseClause>* clauses = stmt->cases();

  SwitchInfo info;
  BytecodeJumpTable* jump_table = nullptr;
  bool use_jump_table = IsSwitchOptimizable(stmt, &info);

  // N_comp_cases is number of cases we will generate comparison jumps for.
  // Note we ignore duplicate cases, since they are very unlikely.

  int n_comp_cases = clauses->length();
  if (use_jump_table) {
    n_comp_cases -= static_cast<int>(info.covered_cases.size());
    jump_table = builder()->AllocateJumpTable(
        info.MaxCase() - info.MinCase() + 1, info.MinCase());
  }

  // Are we still using any if-else bytecodes to evaluate the switch?
  bool use_jumps = n_comp_cases != 0;

  // Does the comparison for non-jump table jumps need an elision scope?
  bool jump_comparison_needs_hole_check_elision_scope = false;

  SwitchBuilder switch_builder(builder(), block_coverage_builder_, stmt,
                               n_comp_cases, jump_table);
  ControlScopeForBreakable scope(this, stmt, &switch_builder);
  builder()->SetStatementPosition(stmt);

  VisitForAccumulatorValue(stmt->tag());

  if (use_jump_table) {
    // Release temps so that they can be reused in clauses.
    RegisterAllocationScope allocation_scope(this);
    // This also fills empty slots in jump table.
    Register r2 = register_allocator()->NewRegister();

    Register r1 = register_allocator()->NewRegister();
    builder()->StoreAccumulatorInRegister(r1);

    builder()->CompareTypeOf(TestTypeOfFlags::LiteralFlag::kNumber);
    switch_builder.JumpToFallThroughIfFalse();
    builder()->LoadAccumulatorWithRegister(r1);

    // TODO(leszeks): Note these are duplicated range checks with the
    // SwitchOnSmi handler for the most part.

    builder()->LoadLiteral(Smi::kMinValue);
    builder()->StoreAccumulatorInRegister(r2);
    builder()->CompareOperation(
        Token::kGreaterThanEq, r1,
        feedback_index(feedback_spec()->AddCompareICSlot()));

    switch_builder.JumpToFallThroughIfFalse();
    builder()->LoadAccumulatorWithRegister(r1);

    builder()->LoadLiteral(Smi::kMaxValue);
    builder()->StoreAccumulatorInRegister(r2);
    builder()->CompareOperation(
        Token::kLessThanEq, r1,
        feedback_index(feedback_spec()->AddCompareICSlot()));

    switch_builder.JumpToFallThroughIfFalse();
    builder()->LoadAccumulatorWithRegister(r1);

    builder()->BinaryOperationSmiLiteral(
        Token::kBitOr, Smi::FromInt(0),
        feedback_index(feedback_spec()->AddBinaryOpICSlot()));

    builder()->StoreAccumulatorInRegister(r2);
    builder()->CompareOperation(
        Token::kEqStrict, r1,
        feedback_index(feedback_spec()->AddCompareICSlot()));

    switch_builder.JumpToFallThroughIfFalse();
    builder()->LoadAccumulatorWithRegister(r2);

    switch_builder.EmitJumpTableIfExists(info.MinCase(), info.MaxCase(),
                                         info.covered_cases);

    if (use_jumps) {
      // When using a jump table, the first jump comparison is conditionally
      // executed if the discriminant wasn't matched by anything in the jump
      // table, and so needs its own elision scope.
      jump_comparison_needs_hole_check_elision_scope = true;
      builder()->LoadAccumulatorWithRegister(r1);
    }
  }

  int case_compare_ctr = 0;
#ifdef DEBUG
  std::unordered_map<int, int> case_ctr_checker;
#endif

  if (use_jumps) {
    Register tag_holder = register_allocator()->NewRegister();
    FeedbackSlot slot = clauses->length() > 0
                            ? feedback_spec()->AddCompareICSlot()
                            : FeedbackSlot::Invalid();
    builder()->StoreAccumulatorInRegister(tag_holder);

    {
      // The comparisons linearly dominate, so no need to open a new elision
      // scope for each one.
      std::optional<HoleCheckElisionScope> elider;
      for (int i = 0; i < clauses->length(); ++i) {
        CaseClause* clause = clauses->at(i);
        if (clause->is_default()) {
          info.default_case = i;
        } else if (!info.CaseExists(clause->label())) {
          if (jump_comparison_needs_hole_check_elision_scope && !elider) {
            elider.emplace(this);
          }

          // Perform label comparison as if via '===' with tag.
          VisitForAccumulatorValue(clause->label());
          builder()->CompareOperation(Token::kEqStrict, tag_holder,
                                      feedback_index(slot));
#ifdef DEBUG
          case_ctr_checker[i] = case_compare_ctr;
#endif
          switch_builder.JumpToCaseIfTrue(ToBooleanMode::kAlreadyBoolean,
                                          case_compare_ctr++);
          // The second and subsequent non-default comparisons are always
          // conditionally executed, and need an elision scope.
          jump_comparison_needs_hole_check_elision_scope = true;
        }
      }
    }
    register_allocator()->ReleaseRegister(tag_holder);
  }

  // For fall-throughs after comparisons (or out-of-range/non-Smi's for jump
  // tables).
  if (info.DefaultExists()) {
    switch_builder.JumpToDefault();
  } else {
    switch_builder.Break();
  }

  // It is only correct to merge hole check states if there is a default clause,
  // as otherwise it's unknown if the switch is exhaustive.
  HoleCheckElisionMergeScope merge_elider(this);

  case_compare_ctr = 0;
  for (int i = 0; i < clauses->length(); ++i) {
    CaseClause* clause = clauses->at(i);
    if (i != info.default_case) {
      if (!info.IsDuplicate(clause)) {
        bool use_table = use_jump_table && info.CaseExists(clause->label());
        if (!use_table) {
// Guarantee that we should generate compare/jump if no table.
#ifdef DEBUG
          DCHECK(case_ctr_checker[i] == case_compare_ctr);
#endif
          switch_builder.BindCaseTargetForCompareJump(case_compare_ctr++,
                                                      clause);
        } else {
          // Use jump table if this is not a duplicate label.
          switch_builder.BindCaseTargetForJumpTable(
              ReduceToSmiSwitchCaseValue(clause->label()), clause);
        }
      }
    } else {
      switch_builder.BindDefault(clause);
    }
    // Regardless, generate code (in case of fall throughs).
    HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
    VisitStatements(clause->statements());
  }

  merge_elider.MergeIf(info.DefaultExists());
}

template <typename TryBodyFunc, typename CatchBodyFunc>
void BytecodeGenerator::BuildTryCatch(
    TryBodyFunc try_body_func, CatchBodyFunc catch_body_func,
    HandlerTable::CatchPrediction catch_prediction,
    TryCatchStatement* stmt_for_coverage) {
  if (builder()->RemainderOfBlockIsDead()) return;

  TryCatchBuilder try_control_builder(
      builder(),
      stmt_for_coverage == nullptr ? nullptr : block_coverage_builder_,
      stmt_for_coverage, catch_prediction);

  // Preserve the context in a dedicated register, so that it can be restored
  // when the handler is entered by the stack-unwinding machinery.
  // TODO(ignition): Be smarter about register allocation.
  Register context = register_allocator()->NewRegister();
  builder()->MoveRegister(Register::current_context(), context);

  // Evaluate the try-block inside a control scope. This simulates a handler
  // that is intercepting 'throw' control commands.
  try_control_builder.BeginTry(context);

  HoleCheckElisionMergeScope merge_elider(this);

  {
    ControlScopeForTryCatch scope(this, &try_control_builder);
    // The try-block itself, even though unconditionally executed, can throw
    // basically at any point, and so must be treated as conditional from the
    // perspective of the hole check elision analysis.
    //
    // try { x } catch (e) { }
    // use(x); <-- Still requires a TDZ check
    //
    // However, if both the try-block and the catch-block emit a hole check,
    // subsequent TDZ checks can be elided.
    //
    // try { x; } catch (e) { x; }
    // use(x); <-- TDZ check can be elided
    HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
    try_body_func();
  }
  try_control_builder.EndTry();

  {
    HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
    catch_body_func(context);
  }

  merge_elider.Merge();

  try_control_builder.EndCatch();
}

template <typename TryBodyFunc, typename FinallyBodyFunc>
void BytecodeGenerator::BuildTryFinally(
    TryBodyFunc try_body_func, FinallyBodyFunc finally_body_func,
    HandlerTable::CatchPrediction catch_prediction,
    TryFinallyStatement* stmt_for_coverage) {
  if (builder()->RemainderOfBlockIsDead()) return;

  // We can't know whether the finally block will override ("catch") an
  // exception thrown in the try block, so we just adopt the outer prediction.
  TryFinallyBuilder try_control_builder(
      builder(),
      stmt_for_coverage == nullptr ? nullptr : block_coverage_builder_,
      stmt_for_coverage, catch_prediction);

  // We keep a record of all paths that enter the finally-block to be able to
  // dispatch to the correct continuation point after the statements in the
  // finally-block have been evaluated.
  //
  // The try-finally construct can enter the finally-block in three ways:
  // 1. By exiting the try-block normally, falling through at the end.
  // 2. By exiting the try-block with a function-local control flow transfer
  //    (i.e. through break/continue/return statements).
  // 3. By exiting the try-block with a thrown exception.
  //
  // The result register semantics depend on how the block was entered:
  //  - ReturnStatement: It represents the return value being returned.
  //  - ThrowStatement: It represents the exception being thrown.
  //  - BreakStatement/ContinueStatement: Undefined and not used.
  //  - Falling through into finally-block: Undefined and not used.
  Register token = register_allocator()->NewRegister();
  Register result = register_allocator()->NewRegister();
  Register message = register_allocator()->NewRegister();
  builder()->LoadTheHole().StoreAccumulatorInRegister(message);
  ControlScope::DeferredCommands commands(this, token, result, message);

  // Preserve the context in a dedicated register, so that it can be
```