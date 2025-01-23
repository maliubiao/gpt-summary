Response: The user wants a summary of the C++ code in `v8/src/interpreter/bytecode-generator.cc`, specifically the functionality covered in part 2 of a 6-part series. If the functionality relates to JavaScript, I need to provide a JavaScript example.

Based on the code snippets:

1. **Generator Function Handling:** The code deals with the generation of bytecode for generator functions, including:
    *   Wrapping the generator body in a try-finally block to ensure the generator is closed when it terminates.
    *   Handling `ReturnStatement` in async generators.
    *   Handling parameter initialization blocks in async generators.
    *   Generating a prologue for generators to dispatch based on their state during resumption.

2. **Function Body Generation:** It generates bytecode for the statements within a function body, including an implicit return if needed. It also handles resource management (`using` declarations) if enabled.

3. **Register Allocation:**  It allocates registers for top-level variables, specifically handling `new.target` and generator objects.

4. **Block Scopes:** It handles the creation of new local block contexts and disposes of resources within block scopes if necessary.

5. **Variable and Function Declarations:**  It generates bytecode for variable and function declarations, initializing variables with `the hole` and handling different variable locations (local, parameter, context, lookup). It also handles module namespace imports.

6. **Module and Global Declarations:** It generates bytecode for module and global declarations, using runtime calls to declare exports and globals.

7. **Statement Processing:** It iterates through and generates bytecode for various statement types like `if`, `continue`, `break`, `return`, `with`, and `switch`.

8. **Switch Statement Optimization:** It includes logic to optimize `switch` statements with Smi literal cases by using jump tables.

9. **Try-Catch and Try-Finally Blocks:**  It generates bytecode for `try-catch` and `try-finally` blocks, handling exception and control flow.

10. **Resource Management (`using`):** It generates bytecode for `using` declarations, ensuring resources are disposed of correctly, even in asynchronous contexts.

11. **Iteration:** It generates bytecode for different loop types (`do-while`, `while`, `for`, `for-in`, `for-of`). The `for-of` section demonstrates desugaring into iterator protocol calls.

12. **Debugger Statement:** Handles the `debugger` statement.

13. **Function and Class Literals:** It generates bytecode for function and class literals, including handling private members and computed property names. It also covers eager compilation of function literals.

Based on these observations, I can formulate a summary and provide relevant JavaScript examples.
这个C++代码文件（`bytecode-generator.cc` 的第2部分）主要负责 **为 JavaScript 代码生成字节码**，特别是针对以下几个方面：

**1. 生成器函数 (Generator Functions) 的处理:**

*   **结构化执行:** 为生成器函数生成 `try-finally` 块，确保在生成器终止时（无论是正常返回还是抛出异常）能执行清理操作，例如关闭生成器。
*   **初始 `yield`:**  处理生成器函数的初始 `yield`，返回实际的生成器对象。
*   **`return` 语句:** 处理生成器函数内部的 `return` 语句，将其参数包装成一个带有 `done: true` 属性的迭代器结果对象。
*   **异步生成器:** 特别处理异步生成器函数中的 `ReturnStatement`，解析 Promise 并返回一个包含解包值的迭代器结果对象。
*   **参数初始化:** 对于异步生成器函数，如果参数不是简单的标识符，则会将参数初始化块添加到 AST 的开头。这段代码会将这个初始化块移出 `try-finally` 块并单独处理。
*   **生成器序言:**  当生成器恢复执行时，会生成一个序言，根据生成器的状态跳转到正确的执行点。

**2. 函数体 (Function Body) 的生成:**

*   **语句生成:**  生成函数体中所有语句的字节码。
*   **隐式返回:** 如果控制流可以到达函数末尾而没有显式的 `return` 语句，则会添加一个隐式的 `return undefined`。
*   **资源管理 (Explicit Resource Management):** 如果启用了显式资源管理 (`using` 声明) 并且存在 `using` 声明，则会将函数体包裹在 `DisposeScope` 中，以确保资源得到正确释放。

**3. 寄存器分配 (Register Allocation):**

*   为顶层变量（如生成器对象或 `new.target`）分配寄存器。

**4. 块级作用域 (Block Scopes) 的处理:**

*   为块级作用域创建新的本地上下文 (context)。
*   在启用了显式资源管理的情况下，处理块级作用域内的资源释放。

**5. 声明 (Declarations) 的处理:**

*   **变量声明:** 为变量声明生成字节码，根据变量的位置（本地、参数、上下文、查找）进行不同的处理，并初始化未初始化的变量为 `the hole`。
*   **函数声明:**  为函数声明生成字节码，包括调用 `VisitFunctionLiteral` 来处理函数字面量，并根据变量的位置进行赋值。
*   **模块命名空间导入:** 处理模块的命名空间导入，调用运行时函数 `kGetModuleNamespace` 获取模块命名空间并赋值给局部变量。
*   **模块和全局声明:** 处理模块和全局声明，调用运行时函数 `kDeclareModuleExports` 和 `kDeclareGlobals` 来声明导出的模块变量和全局变量。

**6. 语句 (Statements) 的处理:**

*   遍历并生成各种语句的字节码，例如：
    *   **表达式语句 (`ExpressionStatement`)**: 计算表达式的值。
    *   **`if` 语句 (`IfStatement`)**:  生成条件跳转指令。
    *   **`continue` 语句 (`ContinueStatement`)**: 生成跳转到循环继续点的指令。
    *   **`break` 语句 (`BreakStatement`)**: 生成跳转到循环或块出口的指令。
    *   **`return` 语句 (`ReturnStatement`)**: 生成返回指令。
    *   **`with` 语句 (`WithStatement`)**: 创建 `with` 语句的作用域。
    *   **`switch` 语句 (`SwitchStatement`)**:  实现 `switch` 语句的逻辑，包括针对 Smi 字面量值的优化，使用跳转表。
    *   **`try-catch` 语句 (`TryCatchStatement`)**:  生成 `try-catch` 块的字节码，包括保存和恢复上下文，以及处理异常。
    *   **`try-finally` 语句 (`TryFinallyStatement`)**: 生成 `try-finally` 块的字节码，确保 `finally` 块始终执行。
    *   **`debugger` 语句 (`DebuggerStatement`)**: 生成触发调试器的指令。
    *   **循环语句 (`DoWhileStatement`, `WhileStatement`, `ForStatement`, `ForInStatement`, `ForOfStatement`)**: 生成各种循环结构的字节码。特别是 `for-of` 语句会被“脱糖”成迭代器协议的调用。

**7. 字面量 (Literals) 的处理:**

*   **函数字面量 (`FunctionLiteral`)**:  为函数字面量生成创建闭包的指令。
*   **类字面量 (`ClassLiteral`)**: 为类字面量生成字节码，包括处理私有成员、计算属性名、静态初始化器等。

**它与 JavaScript 的功能关系以及示例：**

这段代码直接关系到 JavaScript 的以下功能：

*   **生成器函数:**
    ```javascript
    function* myGenerator() {
      yield 1;
      return 2;
    }

    const generator = myGenerator();
    console.log(generator.next()); // { value: 1, done: false }
    console.log(generator.next()); // { value: 2, done: true }
    ```
    这段 C++ 代码负责生成执行 `myGenerator` 函数所需的字节码，包括 `yield` 和 `return` 语句的处理。

*   **异步生成器函数:**
    ```javascript
    async function* myAsyncGenerator() {
      yield await Promise.resolve(1);
      return 2;
    }

    const asyncGenerator = myAsyncGenerator();
    asyncGenerator.next().then(result => console.log(result)); // { value: 1, done: false }
    asyncGenerator.next().then(result => console.log(result)); // { value: 2, done: true }
    ```
    这段代码负责处理异步 `yield` 和异步 `return` 的特殊逻辑。

*   **显式资源管理 (`using`):**
    ```javascript
    class MyResource {
      [Symbol.dispose]() {
        console.log('Resource disposed');
      }
    }

    function myFunction() {
      using res = new MyResource();
      console.log('Using resource');
    }

    myFunction(); // Output: "Using resource", "Resource disposed"
    ```
    C++ 代码中的 `BuildDisposeScope` 负责生成确保 `res` 在 `myFunction` 执行完毕后被 `dispose` 的字节码。

*   **`switch` 语句:**
    ```javascript
    function testSwitch(x) {
      switch (x) {
        case 0:
          console.log('Zero');
          break;
        case 1:
          console.log('One');
          break;
        default:
          console.log('Other');
      }
    }

    testSwitch(0); // Output: "Zero"
    testSwitch(1); // Output: "One"
    testSwitch(2); // Output: "Other"
    ```
    这段 C++ 代码会生成执行 `switch` 语句的字节码，包括可能的跳转表优化。

*   **`try-catch` 和 `try-finally` 语句:**
    ```javascript
    function tryCatchExample() {
      try {
        throw new Error('Something went wrong');
      } catch (e) {
        console.error('Caught an error:', e.message);
      } finally {
        console.log('Finally block executed');
      }
    }

    tryCatchExample();
    ```
    这段 C++ 代码负责生成处理异常和确保 `finally` 块执行的字节码。

*   **`for-of` 循环:**
    ```javascript
    const myArray = [1, 2, 3];
    for (const element of myArray) {
      console.log(element);
    }
    ```
    C++ 代码中 `VisitForOfStatement` 会将这个循环转换为调用迭代器方法 (`GetIterator`, `next`) 的字节码。

*   **类 (Classes):**
    ```javascript
    class MyClass {
      constructor(value) {
        this.value = value;
      }

      getValue() {
        return this.value;
      }
    }

    const instance = new MyClass(10);
    console.log(instance.getValue()); // Output: 10
    ```
    `BuildClassLiteral` 负责生成创建类和其实例所需的字节码，包括构造函数和方法的处理。

总而言之，这段 C++ 代码是 V8 引擎中至关重要的一部分，它将开发者编写的 JavaScript 代码翻译成机器可以执行的低级指令。理解这段代码的功能有助于深入了解 JavaScript 引擎的工作原理。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```
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

  // Preserve the context in a dedicated register, so that it can be restored
  // when the handler is entered by the stack-unwinding machinery.
  // TODO(ignition): Be smarter about register allocation.
  Register context = register_allocator()->NewRegister();
  builder()->MoveRegister(Register::current_context(), context);

  // Evaluate the try-block inside a control scope. This simulates a handler
  // that is intercepting all control commands.
  try_control_builder.BeginTry(context);
  {
    ControlScopeForTryFinally scope(this, &try_control_builder, &commands);
    // The try-block itself, even though unconditionally executed, can throw
    // basically at any point, and so must be treated as conditional from the
    // perspective of the hole check elision analysis.
    HoleCheckElisionScope elider(this);
    try_body_func();
  }
  try_control_builder.EndTry();

  // Record fall-through and exception cases.
  if (!builder()->RemainderOfBlockIsDead()) {
    commands.RecordFallThroughPath();
  }
  try_control_builder.LeaveTry();
  try_control_builder.BeginHandler();
  commands.RecordHandlerReThrowPath();

  try_control_builder.BeginFinally();

  // Evaluate the finally-block.
  finally_body_func(token, result);
  try_control_builder.EndFinally();

  // Dynamic dispatch after the finally-block.
  commands.ApplyDeferredCommands();
}

template <typename WrappedFunc>
void BytecodeGenerator::BuildDisposeScope(WrappedFunc wrapped_func,
                                          bool has_await_using) {
  RegisterAllocationScope allocation_scope(this);
  DisposablesStackScope disposables_stack_scope(this);
  if (has_await_using) {
    set_catch_prediction(info()->scope()->is_repl_mode_scope()
                             ? HandlerTable::UNCAUGHT_ASYNC_AWAIT
                             : HandlerTable::ASYNC_AWAIT);
  }

  BuildTryFinally(
      // Try block
      [&]() { wrapped_func(); },
      // Finally block
      [&](Register body_continuation_token, Register body_continuation_result) {
        if (has_await_using) {
          Register result_register = register_allocator()->NewRegister();
          Register disposable_stack_register =
              register_allocator()->NewRegister();
          builder()->MoveRegister(current_disposables_stack_,
                                  disposable_stack_register);
          LoopBuilder loop_builder(builder(), nullptr, nullptr,
                                   feedback_spec());
          LoopScope loop_scope(this, &loop_builder);

          {
            RegisterAllocationScope allocation_scope(this);
            RegisterList args = register_allocator()->NewRegisterList(4);
            builder()
                ->MoveRegister(disposable_stack_register, args[0])
                .MoveRegister(body_continuation_token, args[1])
                .MoveRegister(body_continuation_result, args[2])
                .LoadLiteral(Smi::FromEnum(
                    DisposableStackResourcesType::kAtLeastOneAsync))
                .StoreAccumulatorInRegister(args[3]);
            builder()->CallRuntime(Runtime::kDisposeDisposableStack, args);
          }

          builder()
              ->StoreAccumulatorInRegister(result_register)
              .LoadTrue()
              .CompareReference(result_register);

          loop_builder.BreakIfTrue(ToBooleanMode::kConvertToBoolean);

          builder()->LoadAccumulatorWithRegister(result_register);
          BuildTryCatch(
              [&]() { BuildAwait(); },
              [&](Register context) {
                RegisterList args = register_allocator()->NewRegisterList(3);
                builder()
                    ->MoveRegister(current_disposables_stack_, args[0])
                    .StoreAccumulatorInRegister(args[1])  // exception
                    .LoadTheHole()
                    .SetPendingMessage()
                    .StoreAccumulatorInRegister(args[2])
                    .CallRuntime(
                        Runtime::kHandleExceptionsInDisposeDisposableStack,
                        args);

                builder()->StoreAccumulatorInRegister(
                    disposable_stack_register);
              },
              catch_prediction());

          loop_builder.BindContinueTarget();
        } else {
          RegisterList args = register_allocator()->NewRegisterList(4);
          builder()
              ->MoveRegister(current_disposables_stack_, args[0])
              .MoveRegister(body_continuation_token, args[1])
              .MoveRegister(body_continuation_result, args[2])
              .LoadLiteral(
                  Smi::FromEnum(DisposableStackResourcesType::kAllSync))
              .StoreAccumulatorInRegister(args[3]);
          builder()->CallRuntime(Runtime::kDisposeDisposableStack, args);
        }
      },
      catch_prediction());
}

void BytecodeGenerator::VisitIterationBody(IterationStatement* stmt,
                                           LoopBuilder* loop_builder) {
  loop_builder->LoopBody();
  ControlScopeForIteration execution_control(this, stmt, loop_builder);
  Visit(stmt->body());
  loop_builder->BindContinueTarget();
}

void BytecodeGenerator::VisitIterationBodyInHoleCheckElisionScope(
    IterationStatement* stmt, LoopBuilder* loop_builder) {
  HoleCheckElisionScope elider(this);
  VisitIterationBody(stmt, loop_builder);
}

void BytecodeGenerator::VisitDoWhileStatement(DoWhileStatement* stmt) {
  LoopBuilder loop_builder(builder(), block_coverage_builder_, stmt,
                           feedback_spec());
  if (stmt->cond()->ToBooleanIsFalse()) {
    // Since we know that the condition is false, we don't create a loop.
    // Therefore, we don't create a LoopScope (and thus we don't create a header
    // and a JumpToHeader). However, we still need to iterate once through the
    // body.
    VisitIterationBodyInHoleCheckElisionScope(stmt, &loop_builder);
  } else if (stmt->cond()->ToBooleanIsTrue()) {
    LoopScope loop_scope(this, &loop_builder);
    VisitIterationBodyInHoleCheckElisionScope(stmt, &loop_builder);
  } else {
    LoopScope loop_scope(this, &loop_builder);
    VisitIterationBodyInHoleCheckElisionScope(stmt, &loop_builder);
    builder()->SetExpressionAsStatementPosition(stmt->cond());
    BytecodeLabels loop_backbranch(zone());
    if (!loop_builder.break_labels()->empty()) {
      // The test may be conditionally executed if there was a break statement
      // inside the loop body, and therefore requires its own elision scope.
      HoleCheckElisionScope elider(this);
      VisitForTest(stmt->cond(), &loop_backbranch, loop_builder.break_labels(),
                   TestFallthrough::kThen);
    } else {
      VisitForTest(stmt->cond(), &loop_backbranch, loop_builder.break_labels(),
                   TestFallthrough::kThen);
    }
    loop_backbranch.Bind(builder());
  }
}

void BytecodeGenerator::VisitWhileStatement(WhileStatement* stmt) {
  LoopBuilder loop_builder(builder(), block_coverage_builder_, stmt,
                           feedback_spec());

  if (stmt->cond()->ToBooleanIsFalse()) {
    // If the condition is false there is no need to generate the loop.
    return;
  }

  LoopScope loop_scope(this, &loop_builder);
  if (!stmt->cond()->ToBooleanIsTrue()) {
    builder()->SetExpressionAsStatementPosition(stmt->cond());
    BytecodeLabels loop_body(zone());
    VisitForTest(stmt->cond(), &loop_body, loop_builder.break_labels(),
                 TestFallthrough::kThen);
    loop_body.Bind(builder());
  }
  VisitIterationBodyInHoleCheckElisionScope(stmt, &loop_builder);
}

void BytecodeGenerator::VisitForStatement(ForStatement* stmt) {
  if (stmt->init() != nullptr) {
    Visit(stmt->init());
  }

  LoopBuilder loop_builder(builder(), block_coverage_builder_, stmt,
                           feedback_spec());
  if (stmt->cond() && stmt->cond()->ToBooleanIsFalse()) {
    // If the condition is known to be false there is no need to generate
    // body, next or condition blocks. Init block should be generated.
    return;
  }

  LoopScope loop_scope(this, &loop_builder);
  if (stmt->cond() && !stmt->cond()->ToBooleanIsTrue()) {
    builder()->SetExpressionAsStatementPosition(stmt->cond());
    BytecodeLabels loop_body(zone());
    VisitForTest(stmt->cond(), &loop_body, loop_builder.break_labels(),
                 TestFallthrough::kThen);
    loop_body.Bind(builder());
  }

  // C-style for loops' textual order differs from dominator order.
  //
  // for (INIT; TEST; NEXT) BODY
  // REST
  //
  //   has the dominator order of
  //
  // INIT dominates TEST dominates BODY dominates NEXT
  //   and
  // INIT dominates TEST dominates REST
  //
  // INIT and TEST are always evaluated and so do not have their own
  // HoleCheckElisionScope. BODY, like all iteration bodies, can contain control
  // flow like breaks or continues, has its own HoleCheckElisionScope. NEXT is
  // therefore conditionally evaluated and also so has its own
  // HoleCheckElisionScope.
  HoleCheckElisionScope elider(this);
  VisitIterationBody(stmt, &loop_builder);
  if (stmt->next() != nullptr) {
    builder()->SetStatementPosition(stmt->next());
    Visit(stmt->next());
  }
}

void BytecodeGenerator::VisitForInStatement(ForInStatement* stmt) {
  if (stmt->subject()->IsNullLiteral() ||
      stmt->subject()->IsUndefinedLiteral()) {
    // ForIn generates lots of code, skip if it wouldn't produce any effects.
    return;
  }

  BytecodeLabel subject_undefined_label;
  FeedbackSlot slot = feedback_spec()->AddForInSlot();

  // Prepare the state for executing ForIn.
  builder()->SetExpressionAsStatementPosition(stmt->subject());
  VisitForAccumulatorValue(stmt->subject());
  builder()->JumpIfUndefinedOrNull(&subject_undefined_label);
  Register receiver = register_allocator()->NewRegister();
  builder()->ToObject(receiver);

  // Used as kRegTriple and kRegPair in ForInPrepare and ForInNext.
  RegisterList triple = register_allocator()->NewRegisterList(3);
  Register cache_length = triple[2];
  builder()->ForInEnumerate(receiver);
  builder()->ForInPrepare(triple, feedback_index(slot));

  // Set up loop counter
  Register index = register_allocator()->NewRegister();
  builder()->LoadLiteral(Smi::zero());
  builder()->StoreAccumulatorInRegister(index);

  // The loop
  {
    LoopBuilder loop_builder(builder(), block_coverage_builder_, stmt,
                             feedback_spec());
    LoopScope loop_scope(this, &loop_builder);
    HoleCheckElisionScope elider(this);
    builder()->SetExpressionAsStatementPosition(stmt->each());
    loop_builder.BreakIfForInDone(index, cache_length);
    builder()->ForInNext(receiver, index, triple.Truncate(2),
                         feedback_index(slot));
    loop_builder.ContinueIfUndefined();

    // Assign accumulator value to the 'each' target.
    {
      EffectResultScope scope(this);
      // Make sure to preserve the accumulator across the PrepareAssignmentLhs
      // call.
      AssignmentLhsData lhs_data = PrepareAssignmentLhs(
          stmt->each(), AccumulatorPreservingMode::kPreserve);
      builder()->SetExpressionPosition(stmt->each());
      BuildAssignment(lhs_data, Token::kAssign, LookupHoistingMode::kNormal);
    }

    {
      Register cache_type = triple[0];
      ForInScope scope(this, stmt, index, cache_type);
      VisitIterationBody(stmt, &loop_builder);
      builder()->ForInStep(index);
    }
  }
  builder()->Bind(&subject_undefined_label);
}

// Desugar a for-of statement into an application of the iteration protocol.
//
// for (EACH of SUBJECT) BODY
//
//   becomes
//
// iterator = %GetIterator(SUBJECT)
// try {
//
//   loop {
//     // Make sure we are considered 'done' if .next(), .done or .value fail.
//     done = true
//     value = iterator.next()
//     if (value.done) break;
//     value = value.value
//     done = false
//
//     EACH = value
//     BODY
//   }
//   done = true
//
// } catch(e) {
//   iteration_continuation = RETHROW
// } finally {
//   %FinalizeIteration(iterator, done, iteration_continuation)
// }
void BytecodeGenerator::VisitForOfStatement(ForOfStatement* stmt) {
  EffectResultScope effect_scope(this);

  builder()->SetExpressionAsStatementPosition(stmt->subject());
  VisitForAccumulatorValue(stmt->subject());

  // Store the iterator in a dedicated register so that it can be closed on
  // exit, and the 'done' value in a dedicated register so that it can be
  // changed and accessed independently of the iteration result.
  IteratorRecord iterator = BuildGetIteratorRecord(stmt->type());
  Register done = register_allocator()->NewRegister();
  builder()->LoadFalse();
  builder()->StoreAccumulatorInRegister(done);

  BuildTryFinally(
      // Try block.
      [&]() {
        LoopBuilder loop_builder(builder(), block_coverage_builder_, stmt,
                                 feedback_spec());
        LoopScope loop_scope(this, &loop_builder);

        // This doesn't need a HoleCheckElisionScope because BuildTryFinally
        // already makes one for try blocks.

        builder()->LoadTrue().StoreAccumulatorInRegister(done);

        {
          RegisterAllocationScope allocation_scope(this);
          Register next_result = register_allocator()->NewRegister();

          // Call the iterator's .next() method. Break from the loop if the
          // `done` property is truthy, otherwise load the value from the
          // iterator result and append the argument.
          builder()->SetExpressionAsStatementPosition(stmt->each());
          BuildIteratorNext(iterator, next_result);
          builder()->LoadNamedProperty(
              next_result, ast_string_constants()->done_string(),
              feedback_index(feedback_spec()->AddLoadICSlot()));
          loop_builder.BreakIfTrue(ToBooleanMode::kConvertToBoolean);

          builder()
              // value = value.value
              ->LoadNamedProperty(
                  next_result, ast_string_constants()->value_string(),
                  feedback_index(feedback_spec()->AddLoadICSlot()));
          // done = false, before the assignment to each happens, so that done
          // is false if the assignment throws.
          builder()
              ->StoreAccumulatorInRegister(next_result)
              .LoadFalse()
              .StoreAccumulatorInRegister(done);

          // Assign to the 'each' target.
          AssignmentLhsData lhs_data = PrepareAssignmentLhs(stmt->each());
          builder()->LoadAccumulatorWithRegister(next_result);
          BuildAssignment(lhs_data, Token::kAssign,
                          LookupHoistingMode::kNormal);
        }

        VisitIterationBody(stmt, &loop_builder);
      },
      // Finally block.
      [&](Register iteration_continuation_token,
          Register iteration_continuation_result) {
        // Finish the iteration in the finally block.
        BuildFinalizeIteration(iterator, done, iteration_continuation_token);
      },
      catch_prediction());
}

void BytecodeGenerator::VisitTryCatchStatement(TryCatchStatement* stmt) {
  // Update catch prediction tracking. The updated catch_prediction value lasts
  // until the end of the try_block in the AST node, and does not apply to the
  // catch_block.
  HandlerTable::CatchPrediction outer_catch_prediction = catch_prediction();
  set_catch_prediction(stmt->GetCatchPrediction(outer_catch_prediction));

  BuildTryCatch(
      // Try body.
      [&]() {
        Visit(stmt->try_block());
        set_catch_prediction(outer_catch_prediction);
      },
      // Catch body.
      [&](Register context) {
        if (stmt->scope()) {
          // Create a catch scope that binds the exception.
          BuildNewLocalCatchContext(stmt->scope());
          builder()->StoreAccumulatorInRegister(context);
        }

        // If requested, clear message object as we enter the catch block.
        if (stmt->ShouldClearException(outer_catch_prediction)) {
          builder()->LoadTheHole().SetPendingMessage();
        }

        // Load the catch context into the accumulator.
        builder()->LoadAccumulatorWithRegister(context);

        // Evaluate the catch-block.
        if (stmt->scope()) {
          VisitInScope(stmt->catch_block(), stmt->scope());
        } else {
          VisitBlock(stmt->catch_block());
        }
      },
      catch_prediction(), stmt);
}

void BytecodeGenerator::VisitTryFinallyStatement(TryFinallyStatement* stmt) {
  BuildTryFinally(
      // Try block.
      [&]() { Visit(stmt->try_block()); },
      // Finally block.
      [&](Register body_continuation_token, Register body_continuation_result) {
        Visit(stmt->finally_block());
      },
      catch_prediction(), stmt);
}

void BytecodeGenerator::VisitDebuggerStatement(DebuggerStatement* stmt) {
  builder()->SetStatementPosition(stmt);
  builder()->Debugger();
}

void BytecodeGenerator::VisitFunctionLiteral(FunctionLiteral* expr) {
  CHECK_LT(info_->literal()->function_literal_id(),
           expr->function_literal_id());
  DCHECK_EQ(expr->scope()->outer_scope(), current_scope());
  uint8_t flags = CreateClosureFlags::Encode(
      expr->pretenure(), closure_scope()->is_function_scope(),
      info()->flags().might_always_turbofan());
  size_t entry = builder()->AllocateDeferredConstantPoolEntry();
  builder()->CreateClosure(entry, GetCachedCreateClosureSlot(expr), flags);
  function_literals_.push_back(std::make_pair(expr, entry));
  AddToEagerLiteralsIfEager(expr);
}

void BytecodeGenerator::AddToEagerLiteralsIfEager(FunctionLiteral* literal) {
  // Only parallel compile when there's a script (not the case for source
  // position collection).
  if (!script_.is_null() && literal->should_parallel_compile()) {
    // If we should normally be eagerly compiling this function, we must be here
    // because of post_parallel_compile_tasks_for_eager_toplevel.
    DCHECK_IMPLIES(
        literal->ShouldEagerCompile(),
        info()->flags().post_parallel_compile_tasks_for_eager_toplevel());
    // There exists a lazy compile dispatcher.
    DCHECK(info()->dispatcher());
    // There exists a cloneable character stream.
    DCHECK(info()->character_stream()->can_be_cloned_for_parallel_access());

    UnparkedScopeIfOnBackground scope(local_isolate_);
    // If there doesn't already exist a SharedFunctionInfo for this function,
    // then create one and enqueue it. Otherwise, we're reparsing (e.g. for the
    // debugger, source position collection, call printing, recompile after
    // flushing, etc.) and don't want to over-compile.
    DirectHandle<SharedFunctionInfo> shared_info =
        Compiler::GetSharedFunctionInfo(literal, script_, local_isolate_);
    if (!shared_info->is_compiled()) {
      info()->dispatcher()->Enqueue(
          local_isolate_, indirect_handle(shared_info, local_isolate_),
          info()->character_stream()->Clone());
    }
  } else if (eager_inner_literals_ && literal->ShouldEagerCompile()) {
    DCHECK(!IsInEagerLiterals(literal, *eager_inner_literals_));
    DCHECK(!literal->should_parallel_compile());
    eager_inner_literals_->push_back(literal);
  }
}

void BytecodeGenerator::BuildClassLiteral(ClassLiteral* expr, Register name) {
  size_t class_boilerplate_entry =
      builder()->AllocateDeferredConstantPoolEntry();
  class_literals_.push_back(std::make_pair(expr, class_boilerplate_entry));

  VisitDeclarations(expr->scope()->declarations());
  Register class_constructor = register_allocator()->NewRegister();

  // Create the class brand symbol and store it on the context during class
  // evaluation. This will be stored in the instance later in the constructor.
  // We do this early so that invalid access to private methods or accessors
  // in computed property keys throw.
  if (expr->scope()->brand() != nullptr) {
    Register brand = register_allocator()->NewRegister();
    const AstRawString* class_name =
        expr->scope()->class_variable() != nullptr
            ? expr->scope()->class_variable()->raw_name()
            : ast_string_constants()->anonymous_string();
    builder()
        ->LoadLiteral(class_name)
        .StoreAccumulatorInRegister(brand)
        .CallRuntime(Runtime::kCreatePrivateBrandSymbol, brand);
    register_allocator()->ReleaseRegister(brand);

    BuildVariableAssignment(expr->scope()->brand(), Token::kInit,
                            HoleCheckMode::kElided);
  }

  AccessorTable<ClassLiteral::Property> private_accessors(zone());
  for (int i = 0; i < expr->private_members()->length(); i++) {
    ClassLiteral::Property* property = expr->private_members()->at(i);
    DCHECK(property->is_private());
    switch (property->kind()) {
      case ClassLiteral::Property::FIELD: {
        // Initialize the private field variables early.
        // Create the private name symbols for fields during class
        // evaluation and store them on the context. These will be
        // used as keys later during instance or static initialization.
        RegisterAllocationScope private_name_register_scope(this);
        Register private_name = register_allocator()->NewRegister();
        VisitForRegisterValue(property->key(), private_name);
        builder()
            ->LoadLiteral(property->key()->AsLiteral()->AsRawPropertyName())
            .StoreAccumulatorInRegister(private_name)
            .CallRuntime(Runtime::kCreatePrivateNameSymbol, private_name);
        DCHECK_NOT_NULL(property->private_name_var());
        BuildVariableAssignment(property->private_name_var(), Token::kInit,
                                HoleCheckMode::kElided);
        break;
      }
      case ClassLiteral::Property::METHOD: {
        RegisterAllocationScope register_scope(this);
        VisitForAccumulatorValue(property->value());
        BuildVariableAssignment(property->private_name_var(), Token::kInit,
                                HoleCheckMode::kElided);
        break;
      }
      // Collect private accessors into a table to merge the creation of
      // those closures later.
      case ClassLiteral::Property::GETTER: {
        Literal* key = property->key()->AsLiteral();
        DCHECK_NULL(private_accessors.LookupOrInsert(key)->getter);
        private_accessors.LookupOrInsert(key)->getter = property;
        break;
      }
      case ClassLiteral::Property::SETTER: {
        Literal* key = property->key()->AsLiteral();
        DCHECK_NULL(private_accessors.LookupOrInsert(key)->setter);
        private_accessors.LookupOrInsert(key)->setter = property;
        break;
      }
      case ClassLiteral::Property::AUTO_ACCESSOR: {
        Literal* key = property->key()->AsLiteral();
        RegisterAllocationScope private_name_register_scope(this);
        Register accessor_storage_private_name =
            register_allocator()->NewRegister();
        Variable* accessor_storage_private_name_var =
            property->auto_accessor_info()
                ->accessor_storage_name_proxy()
                ->var();
        // We reuse the already internalized
        // ".accessor-storage-<accessor_number>" strings that were defined in
        // the parser instead of the "<name>accessor storage" string from the
        // spec. The downsides are that is that these are the property names
        // that will show up in devtools and in error messages.
        // Additionally, a property can share a name with the corresponding
        // property of their parent class, i.e. for classes defined as
        // "class C {accessor x}" and "class D extends C {accessor y}",
        // if "d = new D()", then d.x and d.y will share the name
        // ".accessor-storage-0", (but a different private symbol).
        // TODO(42202709): Get to a resolution on how to handle this naming
        // issue before shipping the feature.
        builder()
            ->LoadLiteral(accessor_storage_private_name_var->raw_name())
            .StoreAccumulatorInRegister(accessor_storage_private_name)
            .CallRuntime(Runtime::kCreatePrivateNameSymbol,
                         accessor_storage_private_name);
        BuildVariableAssignment(accessor_storage_private_name_var, Token::kInit,
                                HoleCheckMode::kElided);
        auto* accessor_pair = private_accessors.LookupOrInsert(key);
        DCHECK_NULL(accessor_pair->getter);
        accessor_pair->getter = property;
        DCHECK_NULL(accessor_pair->setter);
        accessor_pair->setter = property;
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  {
    RegisterAllocationScope register_scope(this);
    RegisterList args = register_allocator()->NewGrowableRegisterList();

    Register class_boilerplate = register_allocator()->GrowRegisterList(&args);
    Register class_constructor_in_args =
        register_allocator()->GrowRegisterList(&args);
    Register super_class = register_allocator()->GrowRegisterList(&args);
    DCHECK_EQ(ClassBoilerplate::kFirstDynamicArgumentIndex,
              args.register_count());

    VisitForAccumulatorValueOrTheHole(expr->extends());
    builder()->StoreAccumulatorInRegister(super_class);

    VisitFunctionLiteral(expr->constructor());
    builder()
        ->StoreAccumulatorInRegister(class_constructor)
        .MoveRegister(class_constructor, class_constructor_in_args)
        .LoadConstantPoolEntry(class_boilerplate_entry)
        .StoreAccumulatorInRegister(class_boilerplate);

    // Create computed names and method values nodes to store into the literal.
    for (int i = 0; i < expr->public_members()->length(); i++) {
      ClassLiteral::Property* property = expr->public_members()->at(i);
      if (property->is_computed_name()) {
        Register key = register_allocator()->GrowRegisterList(&args);

        builder()->SetExpressionAsStatementPosition(property->key());
        BuildLoadPropertyKey(property, key);
        if (property->is_static()) {
          // The static prototype property is read only. We handle the non
          // computed property name case in the parser. Since this is the only
          // case where we need to check for an own read only property we
          // special case this so we do not need to do this for every property.

          FeedbackSlot slot = GetDummyCompareICSlot();
          BytecodeLabel done;
          builder()
              ->LoadLiteral(ast_string_constants()->prototype_string())
              .CompareOperation(Token::kEqStrict, key, feedback_index(slot))
              .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &done)
              .CallRuntime(Runtime::kThrowStaticPrototypeError)
              .Bind(&done);
        }

        if (property->kind() == ClassLiteral::Property::FIELD) {
          DCHECK(!property->is_private());
          // Initialize field's name variable with the computed name.
          DCHECK_NOT_NULL(property->computed_name_var());
          builder()->LoadAccumulatorWithRegister(key);
          BuildVariableAssignment(property->computed_name_var(), Token::kInit,
                                  HoleCheckMode::kElided);
        }
      }

      DCHECK(!property->is_private());

      if (property->kind() == ClassLiteral::Property::FIELD) {
        // We don't compute field's value here, but instead do it in the
        // initializer function.
        continue;
      }

      if (property->kind() == ClassLiteral::Property::AUTO_ACCESSOR) {
        {
          RegisterAllocationScope private_name_register_scope(this);
          Register name_register = register_allocator()->NewRegister();
          Variable* accessor_storage_private_name_var =
              property->auto_accessor_info()
                  ->accessor_storage_name_proxy()
                  ->var();
          builder()
              ->LoadLiteral(accessor_storage_private_name_var->raw_name())
              .StoreAccumulatorInRegister(name_register)
              .CallRuntime(Runtime::kCreatePrivateNameSymbol, name_register);
          BuildVariableAssignment(accessor_storage_private_name_var,
                                  Token::kInit, HoleCheckMode::kElided);
        }

        Register getter = register_allocator()->GrowRegisterList(&args);
        Register setter = register_allocator()->GrowRegisterList(&args);
        AutoAccessorInfo* auto_accessor_info = property->auto_accessor_info();
        VisitForRegisterValue(auto_accessor_info->generated_getter(), getter);
        VisitForRegisterValue(auto_accessor_info->generated_setter(), setter);
        continue;
      }

      Register value = register_allocator()->GrowRegisterList(&args);
      VisitForRegisterValue(property->value(), value);
    }

    builder()->CallRuntime(Runtime::kDefineClass, args);
  }

  // Assign to the home object variable. Accumulator already contains the
  // prototype.
  Variable* home_object_variable = expr->home_object();
  if (home_object_variable != nullptr) {
    DCHECK(home_object_variable->is_used());
    DCHECK(home_object_variable->IsContextSlot());
    BuildVariableAssignment(home_object_variable, Token::kInit,
                            HoleCheckMode::kElided);
  }
  Variable* static_home_object_variable = expr->static_home_object();
  if (static_home_object_variable != nullptr) {
    DCHECK(static_home_object_variable->is_used());
    DCHECK(static_home_object_variable->IsContextSlot());
    builder()->LoadAccumulatorWithRegister(class_constructor);
    BuildVariableAssignment(static_home_object_variable, Token::kInit,
                            HoleCheckMode::kElided);
  }

  // Assign to class variable.
  Variable* class_variable = expr->scope()->class_variable();
  if (class_variable != nullptr && class_variable->is_used()) {
    DCHECK(class_variable->IsStackLocal() || class_variable->IsContextSlot());
    builder()->LoadAccumulatorWithRegister(class_constructor);
    BuildVariableAssignment(class_variable, Token::kInit,
                            HoleCheckMode::kElided);
  }

  // Define private accessors, using only a single call to the runtime for
  // each pair of corresponding getters and setters, in the order the first
  // component is declared.
  for (auto accessors : private_accessors.ordered_accessors()) {
    RegisterAllocationScope inner_register_scope(this);
    RegisterList accessors_reg = register_allocator()->NewRegisterList(2);
    ClassLiteral::Property* getter = accessors.second->getter;
    ClassLiteral::Property* setter = accessors.second->setter;
    Variable* accessor_pair_var;
    if (getter && getter->kind() == ClassLiteral::Property::AUTO_ACCESSOR) {
      DCHECK_EQ(setter, getter);
      AutoAccessorInfo* auto_accessor_info = getter->auto_accessor_info();
      VisitForRegisterValue(auto_accessor_info->generated_getter(),
                            accessors_reg[0]);
      VisitForRegisterValue(auto_accessor_info->generated_setter(),
                            accessors_reg[1]);
      accessor_pair_var =
          auto_accessor_info->property_private_name_proxy()->var();
    } else {
      VisitLiteralAccessor(getter, accessors_reg[0]);
      VisitLiteralAccessor(setter, accessors_reg[1]);
      accessor_pair_var = getter != nullptr ? getter->private_name_var()
                                            : setter->private_name_var();
    }
    builder()->CallRuntime(Runtime::kCreatePrivateAccessors, accessors_reg);
    DCHECK_NOT_NULL(accessor_pair_var);
    BuildVariableAssignment(accessor_pair_var, Token::kInit,
                            HoleCheckMode::kElided);
  }

  if (expr->instance_members_initializer_function() != nullptr) {
    VisitForAccumulatorValue(expr->instance_members_initializer_function());

    FeedbackSlot slot = feedback_spec()->AddStoreICSlot(language_mode());
    builder()
        ->StoreClassFieldsInitializer(class_constructor, feedback_index(slot))
        .LoadAccumulatorWithRegister(class_constructor);
  }

  if (expr->static_initializer() != nullptr) {
    // TODO(gsathya): This can be optimized away to be a part of the
    // class boilerplate in the future. The name argument can be
    // passed to the DefineClass runtime function and have it set
    // there.
    // TODO(v8:13451): Alternatively, port SetFunctionName to an ic so that we
    // can replace the runtime call to a dedicate bytecode here.
    if (name.is_valid()) {
      RegisterAllocationScope inner_register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->MoveRegister(class_constructor, args[0])
          .MoveRegister(name, args[1])
          .CallRuntime(Runtime::kSetFunctionName, args);
    }

    RegisterAllocationScope inner_register_scope(this);
    RegisterList args = register_allocator()->NewRegisterList(1);
    Register initializer = VisitForRegisterValue(expr->static_initializer());

    builder()
        ->MoveRegister(class_constructor, args[0])
        .CallPrope
```