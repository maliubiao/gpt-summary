Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/interpreter/bytecode-generator.cc`. I need to analyze the code and identify its key responsibilities.

Here's a breakdown of the code's actions:

1. **Exception Handling (`BuildTryFinally`, `BuildTryCatch`):** The code includes functions for generating bytecode related to `try...catch` and `try...finally` blocks. This involves setting up control flow for normal execution, handling exceptions, and ensuring the `finally` block executes.

2. **Resource Management (`BuildDisposeScope`):**  The `BuildDisposeScope` function suggests support for resource management, likely related to the `using` keyword and disposable resources. It uses `try...finally` to ensure resources are disposed of correctly, even in the presence of exceptions.

3. **Looping Constructs (`VisitDoWhileStatement`, `VisitWhileStatement`, `VisitForStatement`, `VisitForInStatement`, `VisitForOfStatement`):**  The code contains logic for generating bytecode for different types of loops (`do...while`, `while`, `for`, `for...in`, `for...of`). This involves setting up loop headers, break and continue targets, and handling loop conditions.

4. **Debugger Support (`VisitDebuggerStatement`):** The `VisitDebuggerStatement` function indicates support for the `debugger` statement, allowing breakpoints or debugger invocation.

5. **Function Literals (`VisitFunctionLiteral`):** The code handles the generation of bytecode for function literals (anonymous functions or lambda expressions). This likely involves creating closure objects and managing their scope.

6. **Class Literals (`BuildClassLiteral`):** The extensive `BuildClassLiteral` function suggests it handles the complex process of generating bytecode for class declarations. This includes creating class constructors, defining methods and fields (including private ones), handling inheritance, and managing static members.

Based on these observations, I can formulate the functional summary and address the user's additional questions.
这是 `v8/src/interpreter/bytecode-generator.cc` 源代码的一部分，主要负责为 JavaScript 代码生成 Ignition 字节码。

以下是代码片段的功能归纳：

**核心功能：控制流语句和类声明的字节码生成**

该代码片段主要关注以下两种 JavaScript 结构生成字节码：

1. **异常处理和资源管理：**  处理 `try...catch` 和 `try...finally` 语句，以及用于资源管理的 `using` 声明（通过 `BuildDisposeScope`）。
2. **循环语句：** 处理各种循环结构，如 `do...while`、`while`、`for`、`for...in` 和 `for...of` 循环。
3. **Debugger 语句：**  为 `debugger` 语句生成相应的字节码。
4. **函数字面量：**  为函数字面量（匿名函数、箭头函数等）生成创建闭包的字节码。
5. **类字面量：** 为 `class` 声明生成复杂的字节码，包括构造函数、方法、字段（包括私有字段）、getter/setter、静态成员以及继承等。

**关于提问的补充说明：**

* **`.tq` 结尾：** 如果 `v8/src/interpreter/bytecode-generator.cc` 以 `.tq` 结尾，那它就是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的类型化的元编程语言，用于生成高效的 C++ 代码，包括字节码生成器等关键组件。  然而，当前的 `.cc` 结尾表明这是一个直接用 C++ 编写的源代码文件。

* **与 JavaScript 的关系及示例：**  这段代码直接对应着 JavaScript 的控制流和类声明语法。

    * **`try...catch` 和 `try...finally`:**

      ```javascript
      try {
        // 可能会抛出异常的代码
        console.log("Trying something");
        throw new Error("Oops!");
      } catch (e) {
        // 捕获异常并处理
        console.error("Caught an error:", e.message);
      } finally {
        // 无论是否发生异常都会执行的代码
        console.log("Finally done");
      }
      ```

    * **`using` (资源管理 - 可能需要结合提案理解):**  虽然代码中有 `BuildDisposeScope`，但这通常与 JavaScript 的 `using` 声明（提案中）相关。

      ```javascript
      async function example() {
        await using resource = getResource();
        // 使用 resource
        console.log("Using resource:", resource);
      }
      ```

    * **循环语句：**

      ```javascript
      // do...while
      let i = 0;
      do {
        console.log(i);
        i++;
      } while (i < 3);

      // while
      let j = 0;
      while (j < 3) {
        console.log(j);
        j++;
      }

      // for
      for (let k = 0; k < 3; k++) {
        console.log(k);
      }

      // for...in (遍历对象属性)
      const obj = { a: 1, b: 2 };
      for (const key in obj) {
        console.log(key, obj[key]);
      }

      // for...of (遍历可迭代对象，如数组)
      const arr = [10, 20, 30];
      for (const value of arr) {
        console.log(value);
      }
      ```

    * **`debugger`:**

      ```javascript
      function myFunction(x) {
        debugger; // 代码执行到这里会暂停，方便调试
        console.log("Value of x:", x);
      }
      myFunction(5);
      ```

    * **函数字面量：**

      ```javascript
      // 匿名函数
      const add = function(a, b) { return a + b; };

      // 箭头函数
      const multiply = (a, b) => a * b;
      ```

    * **类声明：**

      ```javascript
      class MyClass {
        constructor(name) {
          this.name = name;
          this.#privateField = "secret";
        }

        greet() {
          console.log(`Hello, ${this.name}!`);
        }

        get privateFieldValue() {
          return this.#privateField;
        }

        set privateFieldValue(value) {
          this.#privateField = value;
        }

        static staticMethod() {
          console.log("Static method called.");
        }

        #privateField; // 私有字段
      }

      const instance = new MyClass("World");
      instance.greet();
      console.log(instance.privateFieldValue);
      MyClass.staticMethod();
      ```

* **代码逻辑推理、假设输入与输出：**  由于这段代码是 V8 内部的实现细节，直接进行代码逻辑推理并给出假设输入输出比较困难。其输入是 AST（抽象语法树），输出是字节码指令序列。  例如，对于一个简单的 `if` 语句，输入可能是代表该 `if` 语句的 AST 节点，输出则是加载条件、跳转指令等字节码。

* **用户常见的编程错误：**  这段代码在底层处理 JavaScript 的语法结构，因此它本身不太会直接导致用户编写代码时的常见错误。但是，它在处理这些结构时，可能会暴露出一些潜在的运行时错误。 例如：

    * **`try...catch` 的使用不当：** 没有正确捕获可能发生的异常，导致程序崩溃。
    * **`finally` 块中的副作用：** 在 `finally` 块中修改了可能在 `try` 块中被修改的变量，导致难以预测的行为。
    * **循环中的无限循环：** 循环条件永远为真，导致程序卡死。
    * **`for...in` 遍历顺序的依赖：**  `for...in` 遍历属性的顺序在不同 JavaScript 引擎中可能不同，不应依赖其顺序。
    * **`for...of` 用于非可迭代对象：**  尝试用 `for...of` 遍历非可迭代对象会抛出错误。
    * **类声明中的语法错误：** 例如，在构造函数之外直接定义字段而没有赋值，或者私有字段的访问不当。

**作为第 4 部分（共 11 部分）的功能归纳：**

考虑到这是字节码生成器的第 4 部分，很可能前面几部分已经处理了更基础的表达式、变量声明等。**这部分主要关注于控制流的实现和更复杂的语言特性（如类）的字节码生成。** 它负责将程序执行的流程和面向对象的结构转换为虚拟机可以理解的指令。  后续的部分可能会涉及函数调用、对象操作、内置函数等方面。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
restored
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