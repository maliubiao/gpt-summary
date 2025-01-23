Response: The user wants a summary of the C++ source code file `v8/src/interpreter/bytecode-generator.cc`. They also want to know how it relates to JavaScript, with an example if applicable. This is the first part of a six-part file.

**Plan:**

1. **Identify the core responsibility:** The file name and the included headers suggest it's responsible for generating bytecode for the V8 interpreter.
2. **Examine key classes and their roles:** Look at the defined classes like `BytecodeGenerator`, `ContextScope`, `ControlScope`, etc., and try to understand their purpose within the bytecode generation process.
3. **Focus on the first part's content:**  Since it's part 1, concentrate on the initial setup and fundamental structures. Classes related to context management and control flow seem prominent.
4. **Relate to JavaScript:** Think about how these C++ structures represent concepts in JavaScript execution, such as scope, control flow statements (if/else, loops, try/catch), and function calls.
5. **Construct a JavaScript example:** Create a simple JavaScript code snippet that would exercise some of the functionality handled by this part of the bytecode generator. Control flow structures and variable scoping are good candidates.
这个C++源代码文件 `bytecode-generator.cc` 的主要功能是**将抽象语法树 (AST) 转换为 V8 解释器可以执行的字节码**。它是 V8 引擎中负责将 JavaScript 代码转化为可执行指令的关键部分。

在这个第一部分中，代码定义了一些**辅助类**，这些类用于在遍历 AST 并生成字节码的过程中管理和跟踪状态信息，主要涉及以下几个方面：

1. **上下文 (Context) 管理:**  `ContextScope` 类用于跟踪和管理 JavaScript 代码执行时的上下文链。这包括跟踪当前的作用域链以及如何在函数调用时创建和销毁新的上下文。
2. **控制流 (Control Flow) 管理:**  `ControlScope` 及其子类 (如 `ControlScopeForTopLevel`, `ControlScopeForBreakable`, `ControlScopeForIteration`, `ControlScopeForTryCatch`, `ControlScopeForTryFinally`, `ControlScopeForDerivedConstructor`) 用于处理 JavaScript 中的控制流语句，如 `break`、`continue`、`return`、`throw` 以及 `try...catch...finally` 等。它们负责生成相应的字节码指令来控制程序的执行流程。
3. **寄存器 (Register) 分配:** `RegisterAllocationScope` 和 `AccumulatorPreservingScope` 用于管理字节码生成过程中使用的寄存器。寄存器用于存储中间计算结果和变量值。
4. **表达式结果 (Expression Result) 处理:** `ExpressionResultScope` 及其子类 (`EffectResultScope`, `ValueResultScope`, `TestResultScope`) 用于确定如何处理表达式的计算结果，例如是丢弃结果（effect）、将结果放入累加器（value）还是用于条件判断（test）。
5. **顶层声明 (Top Level Declarations) 管理:** `TopLevelDeclarationsBuilder` 用于收集和组织顶层（全局或模块级）的变量和函数声明信息，以便在生成字节码时进行处理。
6. **当前作用域 (Current Scope) 管理:** `CurrentScope` 用于在遍历 AST 时跟踪当前的作用域。
7. **多入口块上下文 (Multiple Entry Block Context) 管理:** `MultipleEntryBlockContextScope` 用于处理可能从多个入口进入的代码块的上下文管理。
8. **反馈槽 (Feedback Slot) 缓存:** `FeedbackSlotCache` 用于缓存反馈槽的索引，这些反馈槽用于收集运行时类型信息以进行优化。
9. **空值检查优化 (Hole Check Elision) :** `HoleCheckElisionScope` 和 `HoleCheckElisionMergeScope` 用于优化对未初始化变量的访问检查。
10. **迭代器 (Iterator) 记录:** `IteratorRecord` 用于存储迭代器的相关信息。
11. **可选链 (Optional Chaining) 空值标签管理:** `OptionalChainNullLabelScope` 用于处理可选链操作符 (`?.`) 中的空值情况。
12. **循环 (Loop) 作用域管理:** `LoopScope` 用于标识循环的范围。
13. **`for...in` 作用域管理:** `ForInScope` 用于管理 `for...in` 循环的作用域。
14. **可释放对象栈 (Disposables Stack) 管理:** `DisposablesStackScope` 用于管理可释放对象的栈。

**与 JavaScript 功能的关系及示例:**

这个文件的核心功能是**实现 JavaScript 的语义**，确保 JavaScript 代码按照其定义的规则执行。

**JavaScript 示例：**

```javascript
function example(a) {
  let b = 10;
  if (a > 5) {
    console.log(a + b);
  } else {
    console.log(a - b);
  }
  return a * b;
}
```

**对应的 `bytecode-generator.cc` 中的功能：**

* **`ContextScope`:** 当调用 `example` 函数时，会创建一个新的 `ContextScope` 来管理该函数的局部变量 `b` 的作用域。
* **`ControlScopeForTopLevel` (在函数定义的顶层):**  负责处理函数级别的 `return` 语句。
* **`ControlScopeForBreakable` (用于 `if...else` 语句，虽然在这个例子中没有 `break`):**  负责生成 `if` 和 `else` 分支的字节码，并根据条件跳转到相应的代码块。
* **`RegisterAllocationScope`:**  会为变量 `a` 和 `b` 以及中间计算结果（如 `a + b` 或 `a - b`）分配寄存器。
* **`ValueResultScope`:**  用于处理 `a + b` 和 `a - b` 表达式的计算结果，将其放入累加器中以便后续的 `console.log` 使用。
* **`TopLevelDeclarationsBuilder`:** 如果这是全局作用域下的函数定义，会将 `example` 函数的声明信息记录下来。

**更具体地，针对 `if (a > 5)` 语句：**

* **`TestResultScope`:** 会处理 `a > 5` 这个条件表达式，生成字节码来比较 `a` 和 `5`，并根据比较结果跳转到 `then` 代码块 (`console.log(a + b)`) 或 `else` 代码块 (`console.log(a - b)`)。

总之，`bytecode-generator.cc` 的第一部分定义了在将 JavaScript 代码转化为低级字节码时所需的关键数据结构和机制，为后续的 AST 遍历和字节码生成奠定了基础。它直接关系到 JavaScript 中作用域管理、控制流执行以及变量和表达式的计算等核心功能。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/interpreter/bytecode-generator.h"

#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>

#include "include/v8-extension.h"
#include "src/api/api-inl.h"
#include "src/ast/ast-source-ranges.h"
#include "src/ast/ast.h"
#include "src/ast/scopes.h"
#include "src/builtins/builtins-constructor.h"
#include "src/codegen/compiler.h"
#include "src/codegen/unoptimized-compilation-info.h"
#include "src/common/globals.h"
#include "src/compiler-dispatcher/lazy-compile-dispatcher.h"
#include "src/heap/parked-scope.h"
#include "src/interpreter/bytecode-array-builder.h"
#include "src/interpreter/bytecode-flags-and-tokens.h"
#include "src/interpreter/bytecode-jump-table.h"
#include "src/interpreter/bytecode-label.h"
#include "src/interpreter/bytecode-register-allocator.h"
#include "src/interpreter/bytecode-register-optimizer.h"
#include "src/interpreter/bytecode-register.h"
#include "src/interpreter/control-flow-builders.h"
#include "src/logging/local-logger.h"
#include "src/logging/log.h"
#include "src/numbers/conversions.h"
#include "src/objects/debug-objects.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/objects.h"
#include "src/objects/smi.h"
#include "src/objects/template-objects.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/token.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {
namespace interpreter {

// Scoped class tracking context objects created by the visitor. Represents
// mutations of the context chain within the function body, allowing pushing and
// popping of the current {context_register} during visitation.
class V8_NODISCARD BytecodeGenerator::ContextScope {
 public:
  ContextScope(BytecodeGenerator* generator, Scope* scope,
               Register outer_context_reg = Register())
      : generator_(generator),
        scope_(scope),
        outer_(generator_->execution_context()),
        register_(Register::current_context()),
        depth_(0) {
    DCHECK(scope->NeedsContext() || outer_ == nullptr);
    if (outer_) {
      depth_ = outer_->depth_ + 1;

      // Push the outer context into a new context register.
      if (!outer_context_reg.is_valid()) {
        outer_context_reg = generator_->register_allocator()->NewRegister();
      }
      outer_->set_register(outer_context_reg);
      generator_->builder()->PushContext(outer_context_reg);
    }
    generator_->set_execution_context(this);
  }

  ~ContextScope() {
    if (outer_) {
      DCHECK_EQ(register_.index(), Register::current_context().index());
      generator_->builder()->PopContext(outer_->reg());
      outer_->set_register(register_);
    }
    generator_->set_execution_context(outer_);
  }

  ContextScope(const ContextScope&) = delete;
  ContextScope& operator=(const ContextScope&) = delete;

  // Returns the depth of the given |scope| for the current execution context.
  int ContextChainDepth(Scope* scope) {
    return scope_->ContextChainLength(scope);
  }

  // Returns the execution context at |depth| in the current context chain if it
  // is a function local execution context, otherwise returns nullptr.
  ContextScope* Previous(int depth) {
    if (depth > depth_) {
      return nullptr;
    }

    ContextScope* previous = this;
    for (int i = depth; i > 0; --i) {
      previous = previous->outer_;
    }
    return previous;
  }

  Register reg() const { return register_; }

 private:
  const BytecodeArrayBuilder* builder() const { return generator_->builder(); }

  void set_register(Register reg) { register_ = reg; }

  BytecodeGenerator* generator_;
  Scope* scope_;
  ContextScope* outer_;
  Register register_;
  int depth_;
};

// Scoped class for tracking control statements entered by the
// visitor.
class V8_NODISCARD BytecodeGenerator::ControlScope {
 public:
  explicit ControlScope(BytecodeGenerator* generator)
      : generator_(generator),
        outer_(generator->execution_control()),
        context_(generator->execution_context()) {
    generator_->set_execution_control(this);
  }
  ~ControlScope() { generator_->set_execution_control(outer()); }
  ControlScope(const ControlScope&) = delete;
  ControlScope& operator=(const ControlScope&) = delete;

  void Break(Statement* stmt) {
    PerformCommand(CMD_BREAK, stmt, kNoSourcePosition);
  }
  void Continue(Statement* stmt) {
    PerformCommand(CMD_CONTINUE, stmt, kNoSourcePosition);
  }
  void ReturnAccumulator(int source_position) {
    PerformCommand(CMD_RETURN, nullptr, source_position);
  }
  void AsyncReturnAccumulator(int source_position) {
    PerformCommand(CMD_ASYNC_RETURN, nullptr, source_position);
  }

  class DeferredCommands;

 protected:
  enum Command {
    CMD_BREAK,
    CMD_CONTINUE,
    CMD_RETURN,
    CMD_ASYNC_RETURN,
    CMD_RETHROW
  };
  static constexpr bool CommandUsesAccumulator(Command command) {
    return command != CMD_BREAK && command != CMD_CONTINUE;
  }

  void PerformCommand(Command command, Statement* statement,
                      int source_position);
  virtual bool Execute(Command command, Statement* statement,
                       int source_position) = 0;

  // Helper to pop the context chain to a depth expected by this control scope.
  // Note that it is the responsibility of each individual {Execute} method to
  // trigger this when commands are handled and control-flow continues locally.
  void PopContextToExpectedDepth();

  BytecodeGenerator* generator() const { return generator_; }
  ControlScope* outer() const { return outer_; }
  ContextScope* context() const { return context_; }

 private:
  BytecodeGenerator* generator_;
  ControlScope* outer_;
  ContextScope* context_;
};

// Helper class for a try-finally control scope. It can record intercepted
// control-flow commands that cause entry into a finally-block, and re-apply
// them after again leaving that block. Special tokens are used to identify
// paths going through the finally-block to dispatch after leaving the block.
class V8_NODISCARD BytecodeGenerator::ControlScope::DeferredCommands final {
 public:
  DeferredCommands(BytecodeGenerator* generator, Register token_register,
                   Register result_register, Register message_register)
      : generator_(generator),
        deferred_(generator->zone()),
        token_register_(token_register),
        result_register_(result_register),
        message_register_(message_register),
        return_token_(-1),
        async_return_token_(-1),
        fallthrough_from_try_block_needed_(false) {
    // There's always a rethrow path.
    // TODO(leszeks): We could decouple deferred_ index and token to allow us
    // to still push this lazily.
    static_assert(
        static_cast<int>(TryFinallyContinuationToken::kRethrowToken) == 0);
    deferred_.push_back(
        {CMD_RETHROW, nullptr,
         static_cast<int>(TryFinallyContinuationToken::kRethrowToken)});
  }

  // One recorded control-flow command.
  struct Entry {
    Command command;       // The command type being applied on this path.
    Statement* statement;  // The target statement for the command or {nullptr}.
    int token;             // A token identifying this particular path.
  };

  // Records a control-flow command while entering the finally-block. This also
  // generates a new dispatch token that identifies one particular path. This
  // expects the result to be in the accumulator.
  void RecordCommand(Command command, Statement* statement) {
    int token = GetTokenForCommand(command, statement);

    DCHECK_LT(token, deferred_.size());
    DCHECK_EQ(deferred_[token].command, command);
    DCHECK_EQ(deferred_[token].statement, statement);
    DCHECK_EQ(deferred_[token].token, token);

    if (CommandUsesAccumulator(command)) {
      builder()->StoreAccumulatorInRegister(result_register_);
    }
    builder()->LoadLiteral(Smi::FromInt(token));
    builder()->StoreAccumulatorInRegister(token_register_);
    if (!CommandUsesAccumulator(command)) {
      // If we're not saving the accumulator in the result register, shove a
      // harmless value there instead so that it is still considered "killed" in
      // the liveness analysis. Normally we would LdaUndefined first, but the
      // Smi token value is just as good, and by reusing it we save a bytecode.
      builder()->StoreAccumulatorInRegister(result_register_);
    }
    if (command == CMD_RETHROW) {
      // Clear message object as we enter the catch block. It will be restored
      // if we rethrow.
      builder()->LoadTheHole().SetPendingMessage().StoreAccumulatorInRegister(
          message_register_);
    }
  }

  // Records the dispatch token to be used to identify the re-throw path when
  // the finally-block has been entered through the exception handler. This
  // expects the exception to be in the accumulator.
  void RecordHandlerReThrowPath() {
    // The accumulator contains the exception object.
    RecordCommand(CMD_RETHROW, nullptr);
  }

  // Records the dispatch token to be used to identify the implicit fall-through
  // path at the end of a try-block into the corresponding finally-block.
  void RecordFallThroughPath() {
    fallthrough_from_try_block_needed_ = true;
    builder()->LoadLiteral(Smi::FromInt(
        static_cast<int>(TryFinallyContinuationToken::kFallthroughToken)));
    builder()->StoreAccumulatorInRegister(token_register_);
    // Since we're not saving the accumulator in the result register, shove a
    // harmless value there instead so that it is still considered "killed" in
    // the liveness analysis. Normally we would LdaUndefined first, but the Smi
    // token value is just as good, and by reusing it we save a bytecode.
    builder()->StoreAccumulatorInRegister(result_register_);
  }

  void ApplyDeferredCommand(const Entry& entry) {
    if (entry.command == CMD_RETHROW) {
      // Pending message object is restored on exit.
      builder()
          ->LoadAccumulatorWithRegister(message_register_)
          .SetPendingMessage();
    }

    if (CommandUsesAccumulator(entry.command)) {
      builder()->LoadAccumulatorWithRegister(result_register_);
    }
    execution_control()->PerformCommand(entry.command, entry.statement,
                                        kNoSourcePosition);
  }

  // Applies all recorded control-flow commands after the finally-block again.
  // This generates a dynamic dispatch on the token from the entry point.
  void ApplyDeferredCommands() {
    if (deferred_.empty()) return;

    BytecodeLabel fall_through_from_try_block;

    if (deferred_.size() == 1) {
      // For a single entry, just jump to the fallthrough if we don't match the
      // entry token.
      const Entry& entry = deferred_[0];

      if (fallthrough_from_try_block_needed_) {
        builder()
            ->LoadLiteral(Smi::FromInt(entry.token))
            .CompareReference(token_register_)
            .JumpIfFalse(ToBooleanMode::kAlreadyBoolean,
                         &fall_through_from_try_block);
      }

      ApplyDeferredCommand(entry);
    } else {
      // For multiple entries, build a jump table and switch on the token,
      // jumping to the fallthrough if none of them match.
      //
      // If fallthrough from the try block is not needed, generate a jump table
      // with one (1) fewer entries and reuse the fallthrough path for the final
      // entry.
      const int jump_table_base_value =
          fallthrough_from_try_block_needed_ ? 0 : 1;
      const int jump_table_size =
          static_cast<int>(deferred_.size() - jump_table_base_value);

      if (jump_table_size == 1) {
        DCHECK_EQ(2, deferred_.size());
        BytecodeLabel fall_through_to_final_entry;
        const Entry& first_entry = deferred_[0];
        const Entry& final_entry = deferred_[1];
        builder()
            ->LoadLiteral(Smi::FromInt(first_entry.token))
            .CompareReference(token_register_)
            .JumpIfFalse(ToBooleanMode::kAlreadyBoolean,
                         &fall_through_to_final_entry);
        ApplyDeferredCommand(first_entry);
        builder()->Bind(&fall_through_to_final_entry);
        ApplyDeferredCommand(final_entry);
      } else {
        BytecodeJumpTable* jump_table = builder()->AllocateJumpTable(
            jump_table_size, jump_table_base_value);
        builder()
            ->LoadAccumulatorWithRegister(token_register_)
            .SwitchOnSmiNoFeedback(jump_table);

        const Entry& first_entry = deferred_.front();
        if (fallthrough_from_try_block_needed_) {
          builder()->Jump(&fall_through_from_try_block);
          builder()->Bind(jump_table, first_entry.token);
        }
        ApplyDeferredCommand(first_entry);

        for (const Entry& entry : base::IterateWithoutFirst(deferred_)) {
          builder()->Bind(jump_table, entry.token);
          ApplyDeferredCommand(entry);
        }
      }
    }

    if (fallthrough_from_try_block_needed_) {
      builder()->Bind(&fall_through_from_try_block);
    }
  }

  BytecodeArrayBuilder* builder() { return generator_->builder(); }
  ControlScope* execution_control() { return generator_->execution_control(); }

 private:
  int GetTokenForCommand(Command command, Statement* statement) {
    switch (command) {
      case CMD_RETURN:
        return GetReturnToken();
      case CMD_ASYNC_RETURN:
        return GetAsyncReturnToken();
      case CMD_RETHROW:
        return static_cast<int>(TryFinallyContinuationToken::kRethrowToken);
      default:
        // TODO(leszeks): We could also search for entries with the same
        // command and statement.
        return GetNewTokenForCommand(command, statement);
    }
  }

  int GetReturnToken() {
    if (return_token_ == -1) {
      return_token_ = GetNewTokenForCommand(CMD_RETURN, nullptr);
    }
    return return_token_;
  }

  int GetAsyncReturnToken() {
    if (async_return_token_ == -1) {
      async_return_token_ = GetNewTokenForCommand(CMD_ASYNC_RETURN, nullptr);
    }
    return async_return_token_;
  }

  int GetNewTokenForCommand(Command command, Statement* statement) {
    int token = static_cast<int>(deferred_.size());
    deferred_.push_back({command, statement, token});
    return token;
  }

  BytecodeGenerator* generator_;
  ZoneVector<Entry> deferred_;
  Register token_register_;
  Register result_register_;
  Register message_register_;

  // Tokens for commands that don't need a statement.
  int return_token_;
  int async_return_token_;

  // Whether a fallthrough is possible.
  bool fallthrough_from_try_block_needed_;
};

// Scoped class for dealing with control flow reaching the function level.
class BytecodeGenerator::ControlScopeForTopLevel final
    : public BytecodeGenerator::ControlScope {
 public:
  explicit ControlScopeForTopLevel(BytecodeGenerator* generator)
      : ControlScope(generator) {}

 protected:
  bool Execute(Command command, Statement* statement,
               int source_position) override {
    switch (command) {
      case CMD_BREAK:  // We should never see break/continue in top-level.
      case CMD_CONTINUE:
        UNREACHABLE();
      case CMD_RETURN:
        // No need to pop contexts, execution leaves the method body.
        generator()->BuildReturn(source_position);
        return true;
      case CMD_ASYNC_RETURN:
        // No need to pop contexts, execution leaves the method body.
        generator()->BuildAsyncReturn(source_position);
        return true;
      case CMD_RETHROW:
        // No need to pop contexts, execution leaves the method body.
        generator()->BuildReThrow();
        return true;
    }
    return false;
  }
};

// Scoped class for enabling break inside blocks and switch blocks.
class BytecodeGenerator::ControlScopeForBreakable final
    : public BytecodeGenerator::ControlScope {
 public:
  ControlScopeForBreakable(BytecodeGenerator* generator,
                           BreakableStatement* statement,
                           BreakableControlFlowBuilder* control_builder)
      : ControlScope(generator),
        statement_(statement),
        control_builder_(control_builder) {}

 protected:
  bool Execute(Command command, Statement* statement,
               int source_position) override {
    if (statement != statement_) return false;
    switch (command) {
      case CMD_BREAK:
        PopContextToExpectedDepth();
        control_builder_->Break();
        return true;
      case CMD_CONTINUE:
      case CMD_RETURN:
      case CMD_ASYNC_RETURN:
      case CMD_RETHROW:
        break;
    }
    return false;
  }

 private:
  Statement* statement_;
  BreakableControlFlowBuilder* control_builder_;
};

// Scoped class for enabling 'break' and 'continue' in iteration
// constructs, e.g. do...while, while..., for...
class BytecodeGenerator::ControlScopeForIteration final
    : public BytecodeGenerator::ControlScope {
 public:
  ControlScopeForIteration(BytecodeGenerator* generator,
                           IterationStatement* statement,
                           LoopBuilder* loop_builder)
      : ControlScope(generator),
        statement_(statement),
        loop_builder_(loop_builder) {}

 protected:
  bool Execute(Command command, Statement* statement,
               int source_position) override {
    if (statement != statement_) return false;
    switch (command) {
      case CMD_BREAK:
        PopContextToExpectedDepth();
        loop_builder_->Break();
        return true;
      case CMD_CONTINUE:
        PopContextToExpectedDepth();
        loop_builder_->Continue();
        return true;
      case CMD_RETURN:
      case CMD_ASYNC_RETURN:
      case CMD_RETHROW:
        break;
    }
    return false;
  }

 private:
  Statement* statement_;
  LoopBuilder* loop_builder_;
};

// Scoped class for enabling 'throw' in try-catch constructs.
class BytecodeGenerator::ControlScopeForTryCatch final
    : public BytecodeGenerator::ControlScope {
 public:
  ControlScopeForTryCatch(BytecodeGenerator* generator,
                          TryCatchBuilder* try_catch_builder)
      : ControlScope(generator) {}

 protected:
  bool Execute(Command command, Statement* statement,
               int source_position) override {
    switch (command) {
      case CMD_BREAK:
      case CMD_CONTINUE:
      case CMD_RETURN:
      case CMD_ASYNC_RETURN:
        break;
      case CMD_RETHROW:
        // No need to pop contexts, execution re-enters the method body via the
        // stack unwinding mechanism which itself restores contexts correctly.
        generator()->BuildReThrow();
        return true;
    }
    return false;
  }
};

// Scoped class for enabling control flow through try-finally constructs.
class BytecodeGenerator::ControlScopeForTryFinally final
    : public BytecodeGenerator::ControlScope {
 public:
  ControlScopeForTryFinally(BytecodeGenerator* generator,
                            TryFinallyBuilder* try_finally_builder,
                            DeferredCommands* commands)
      : ControlScope(generator),
        try_finally_builder_(try_finally_builder),
        commands_(commands) {}

 protected:
  bool Execute(Command command, Statement* statement,
               int source_position) override {
    switch (command) {
      case CMD_BREAK:
      case CMD_CONTINUE:
      case CMD_RETURN:
      case CMD_ASYNC_RETURN:
      case CMD_RETHROW:
        PopContextToExpectedDepth();
        // We don't record source_position here since we don't generate return
        // bytecode right here and will generate it later as part of finally
        // block. Each return bytecode generated in finally block will get own
        // return source position from corresponded return statement or we'll
        // use end of function if no return statement is presented.
        commands_->RecordCommand(command, statement);
        try_finally_builder_->LeaveTry();
        return true;
    }
    return false;
  }

 private:
  TryFinallyBuilder* try_finally_builder_;
  DeferredCommands* commands_;
};

// Scoped class for collecting 'return' statments in a derived constructor.
// Derived constructors can only return undefined or objects, and this check
// must occur right before return (e.g., after `finally` blocks execute).
class BytecodeGenerator::ControlScopeForDerivedConstructor final
    : public BytecodeGenerator::ControlScope {
 public:
  ControlScopeForDerivedConstructor(BytecodeGenerator* generator,
                                    Register result_register,
                                    BytecodeLabels* check_return_value_labels)
      : ControlScope(generator),
        result_register_(result_register),
        check_return_value_labels_(check_return_value_labels) {}

 protected:
  bool Execute(Command command, Statement* statement,
               int source_position) override {
    // Constructors are never async.
    DCHECK_NE(CMD_ASYNC_RETURN, command);
    if (command == CMD_RETURN) {
      PopContextToExpectedDepth();
      generator()->builder()->SetStatementPosition(source_position);
      generator()->builder()->StoreAccumulatorInRegister(result_register_);
      generator()->builder()->Jump(check_return_value_labels_->New());
      return true;
    }
    return false;
  }

 private:
  Register result_register_;
  BytecodeLabels* check_return_value_labels_;
};

// Allocate and fetch the coverage indices tracking NaryLogical Expressions.
class BytecodeGenerator::NaryCodeCoverageSlots {
 public:
  NaryCodeCoverageSlots(BytecodeGenerator* generator, NaryOperation* expr)
      : generator_(generator) {
    if (generator_->block_coverage_builder_ == nullptr) return;
    for (size_t i = 0; i < expr->subsequent_length(); i++) {
      coverage_slots_.push_back(
          generator_->AllocateNaryBlockCoverageSlotIfEnabled(expr, i));
    }
  }

  int GetSlotFor(size_t subsequent_expr_index) const {
    if (generator_->block_coverage_builder_ == nullptr) {
      return BlockCoverageBuilder::kNoCoverageArraySlot;
    }
    DCHECK(coverage_slots_.size() > subsequent_expr_index);
    return coverage_slots_[subsequent_expr_index];
  }

 private:
  BytecodeGenerator* generator_;
  std::vector<int> coverage_slots_;
};

void BytecodeGenerator::ControlScope::PerformCommand(Command command,
                                                     Statement* statement,
                                                     int source_position) {
  ControlScope* current = this;
  do {
    if (current->Execute(command, statement, source_position)) {
      return;
    }
    current = current->outer();
  } while (current != nullptr);
  UNREACHABLE();
}

void BytecodeGenerator::ControlScope::PopContextToExpectedDepth() {
  // Pop context to the expected depth. Note that this can in fact pop multiple
  // contexts at once because the {PopContext} bytecode takes a saved register.
  if (generator()->execution_context() != context()) {
    generator()->builder()->PopContext(context()->reg());
  }
}

class V8_NODISCARD BytecodeGenerator::RegisterAllocationScope final {
 public:
  explicit RegisterAllocationScope(BytecodeGenerator* generator)
      : generator_(generator),
        outer_next_register_index_(
            generator->register_allocator()->next_register_index()) {}

  ~RegisterAllocationScope() {
    generator_->register_allocator()->ReleaseRegisters(
        outer_next_register_index_);
  }

  RegisterAllocationScope(const RegisterAllocationScope&) = delete;
  RegisterAllocationScope& operator=(const RegisterAllocationScope&) = delete;

  BytecodeGenerator* generator() const { return generator_; }

 private:
  BytecodeGenerator* generator_;
  int outer_next_register_index_;
};

class V8_NODISCARD BytecodeGenerator::AccumulatorPreservingScope final {
 public:
  explicit AccumulatorPreservingScope(BytecodeGenerator* generator,
                                      AccumulatorPreservingMode mode)
      : generator_(generator) {
    if (mode == AccumulatorPreservingMode::kPreserve) {
      saved_accumulator_register_ =
          generator_->register_allocator()->NewRegister();
      generator_->builder()->StoreAccumulatorInRegister(
          saved_accumulator_register_);
    }
  }

  ~AccumulatorPreservingScope() {
    if (saved_accumulator_register_.is_valid()) {
      generator_->builder()->LoadAccumulatorWithRegister(
          saved_accumulator_register_);
    }
  }

  AccumulatorPreservingScope(const AccumulatorPreservingScope&) = delete;
  AccumulatorPreservingScope& operator=(const AccumulatorPreservingScope&) =
      delete;

 private:
  BytecodeGenerator* generator_;
  Register saved_accumulator_register_;
};

// Scoped base class for determining how the result of an expression will be
// used.
class V8_NODISCARD BytecodeGenerator::ExpressionResultScope {
 public:
  ExpressionResultScope(BytecodeGenerator* generator, Expression::Context kind)
      : outer_(generator->execution_result()),
        allocator_(generator),
        kind_(kind),
        type_hint_(TypeHint::kUnknown) {
    generator->set_execution_result(this);
  }

  ~ExpressionResultScope() {
    allocator_.generator()->set_execution_result(outer_);
  }

  ExpressionResultScope(const ExpressionResultScope&) = delete;
  ExpressionResultScope& operator=(const ExpressionResultScope&) = delete;

  bool IsEffect() const { return kind_ == Expression::kEffect; }
  bool IsValue() const { return kind_ == Expression::kValue; }
  bool IsTest() const { return kind_ == Expression::kTest; }

  TestResultScope* AsTest() {
    DCHECK(IsTest());
    return reinterpret_cast<TestResultScope*>(this);
  }

  // Specify expression always returns a Boolean result value.
  void SetResultIsBoolean() {
    DCHECK_EQ(type_hint_, TypeHint::kUnknown);
    type_hint_ = TypeHint::kBoolean;
  }

  void SetResultIsString() {
    DCHECK_EQ(type_hint_, TypeHint::kUnknown);
    type_hint_ = TypeHint::kString;
  }

  void SetResultIsInternalizedString() {
    DCHECK_EQ(type_hint_, TypeHint::kUnknown);
    type_hint_ = TypeHint::kInternalizedString;
  }

  TypeHint type_hint() const { return type_hint_; }

 private:
  ExpressionResultScope* outer_;
  RegisterAllocationScope allocator_;
  Expression::Context kind_;
  TypeHint type_hint_;
};

// Scoped class used when the result of the current expression is not
// expected to produce a result.
class BytecodeGenerator::EffectResultScope final
    : public ExpressionResultScope {
 public:
  explicit EffectResultScope(BytecodeGenerator* generator)
      : ExpressionResultScope(generator, Expression::kEffect) {}
};

// Scoped class used when the result of the current expression to be
// evaluated should go into the interpreter's accumulator.
class V8_NODISCARD BytecodeGenerator::ValueResultScope final
    : public ExpressionResultScope {
 public:
  explicit ValueResultScope(BytecodeGenerator* generator)
      : ExpressionResultScope(generator, Expression::kValue) {}
};

// Scoped class used when the result of the current expression to be
// evaluated is only tested with jumps to two branches.
class V8_NODISCARD BytecodeGenerator::TestResultScope final
    : public ExpressionResultScope {
 public:
  TestResultScope(BytecodeGenerator* generator, BytecodeLabels* then_labels,
                  BytecodeLabels* else_labels, TestFallthrough fallthrough)
      : ExpressionResultScope(generator, Expression::kTest),
        result_consumed_by_test_(false),
        fallthrough_(fallthrough),
        then_labels_(then_labels),
        else_labels_(else_labels) {}

  TestResultScope(const TestResultScope&) = delete;
  TestResultScope& operator=(const TestResultScope&) = delete;

  // Used when code special cases for TestResultScope and consumes any
  // possible value by testing and jumping to a then/else label.
  void SetResultConsumedByTest() { result_consumed_by_test_ = true; }
  bool result_consumed_by_test() { return result_consumed_by_test_; }

  // Inverts the control flow of the operation, swapping the then and else
  // labels and the fallthrough.
  void InvertControlFlow() {
    std::swap(then_labels_, else_labels_);
    fallthrough_ = inverted_fallthrough();
  }

  BytecodeLabel* NewThenLabel() { return then_labels_->New(); }
  BytecodeLabel* NewElseLabel() { return else_labels_->New(); }

  BytecodeLabels* then_labels() const { return then_labels_; }
  BytecodeLabels* else_labels() const { return else_labels_; }

  void set_then_labels(BytecodeLabels* then_labels) {
    then_labels_ = then_labels;
  }
  void set_else_labels(BytecodeLabels* else_labels) {
    else_labels_ = else_labels;
  }

  TestFallthrough fallthrough() const { return fallthrough_; }
  TestFallthrough inverted_fallthrough() const {
    switch (fallthrough_) {
      case TestFallthrough::kThen:
        return TestFallthrough::kElse;
      case TestFallthrough::kElse:
        return TestFallthrough::kThen;
      default:
        return TestFallthrough::kNone;
    }
  }
  void set_fallthrough(TestFallthrough fallthrough) {
    fallthrough_ = fallthrough;
  }

 private:
  bool result_consumed_by_test_;
  TestFallthrough fallthrough_;
  BytecodeLabels* then_labels_;
  BytecodeLabels* else_labels_;
};

// Used to build a list of toplevel declaration data.
class BytecodeGenerator::TopLevelDeclarationsBuilder final : public ZoneObject {
 public:
  template <typename IsolateT>
  Handle<FixedArray> AllocateDeclarations(UnoptimizedCompilationInfo* info,
                                          BytecodeGenerator* generator,
                                          Handle<Script> script,
                                          IsolateT* isolate) {
    DCHECK(has_constant_pool_entry_);

    Handle<FixedArray> data =
        isolate->factory()->NewFixedArray(entry_slots_, AllocationType::kOld);

    int array_index = 0;
    if (info->scope()->is_module_scope()) {
      for (Declaration* decl : *info->scope()->declarations()) {
        Variable* var = decl->var();
        if (!var->is_used()) continue;
        if (var->location() != VariableLocation::MODULE) continue;
#ifdef DEBUG
        int start = array_index;
#endif
        if (decl->IsFunctionDeclaration()) {
          FunctionLiteral* f = static_cast<FunctionDeclaration*>(decl)->fun();
          DirectHandle<SharedFunctionInfo> sfi(
              Compiler::GetSharedFunctionInfo(f, script, isolate));
          // Return a null handle if any initial values can't be created. Caller
          // will set stack overflow.
          if (sfi.is_null()) return Handle<FixedArray>();
          data->set(array_index++, *sfi);
          int literal_index = generator->GetCachedCreateClosureSlot(f);
          data->set(array_index++, Smi::FromInt(literal_index));
          DCHECK(var->IsExport());
          data->set(array_index++, Smi::FromInt(var->index()));
          DCHECK_EQ(start + kModuleFunctionDeclarationSize, array_index);
        } else if (var->IsExport() && var->binding_needs_init()) {
          data->set(array_index++, Smi::FromInt(var->index()));
          DCHECK_EQ(start + kModuleVariableDeclarationSize, array_index);
        }
      }
    } else {
      for (Declaration* decl : *info->scope()->declarations()) {
        Variable* var = decl->var();
        if (!var->is_used()) continue;
        if (var->location() != VariableLocation::UNALLOCATED) continue;
#ifdef DEBUG
        int start = array_index;
#endif
        if (decl->IsVariableDeclaration()) {
          data->set(array_index++, *var->raw_name()->string());
          DCHECK_EQ(start + kGlobalVariableDeclarationSize, array_index);
        } else {
          FunctionLiteral* f = static_cast<FunctionDeclaration*>(decl)->fun();
          DirectHandle<SharedFunctionInfo> sfi(
              Compiler::GetSharedFunctionInfo(f, script, isolate));
          // Return a null handle if any initial values can't be created. Caller
          // will set stack overflow.
          if (sfi.is_null()) return Handle<FixedArray>();
          data->set(array_index++, *sfi);
          int literal_index = generator->GetCachedCreateClosureSlot(f);
          data->set(array_index++, Smi::FromInt(literal_index));
          DCHECK_EQ(start + kGlobalFunctionDeclarationSize, array_index);
        }
      }
    }
    DCHECK_EQ(array_index, data->length());
    return data;
  }

  size_t constant_pool_entry() {
    DCHECK(has_constant_pool_entry_);
    return constant_pool_entry_;
  }

  void set_constant_pool_entry(size_t constant_pool_entry) {
    DCHECK(has_top_level_declaration());
    DCHECK(!has_constant_pool_entry_);
    constant_pool_entry_ = constant_pool_entry;
    has_constant_pool_entry_ = true;
  }

  void record_global_variable_declaration() {
    entry_slots_ += kGlobalVariableDeclarationSize;
  }
  void record_global_function_declaration() {
    entry_slots_ += kGlobalFunctionDeclarationSize;
  }
  void record_module_variable_declaration() {
    entry_slots_ += kModuleVariableDeclarationSize;
  }
  void record_module_function_declaration() {
    entry_slots_ += kModuleFunctionDeclarationSize;
  }
  bool has_top_level_declaration() { return entry_slots_ > 0; }
  bool processed() { return processed_; }
  void mark_processed() { processed_ = true; }

 private:
  const int kGlobalVariableDeclarationSize = 1;
  const int kGlobalFunctionDeclarationSize = 2;
  const int kModuleVariableDeclarationSize = 1;
  const int kModuleFunctionDeclarationSize = 3;

  size_t constant_pool_entry_ = 0;
  int entry_slots_ = 0;
  bool has_constant_pool_entry_ = false;
  bool processed_ = false;
};

class V8_NODISCARD BytecodeGenerator::CurrentScope final {
 public:
  CurrentScope(BytecodeGenerator* generator, Scope* scope)
      : generator_(generator), outer_scope_(generator->current_scope()) {
    if (scope != nullptr) {
      DCHECK_EQ(outer_scope_, scope->outer_scope());
      generator_->set_current_scope(scope);
    }
  }
  ~CurrentScope() {
    if (outer_scope_ != generator_->current_scope()) {
      generator_->set_current_scope(outer_scope_);
    }
  }
  CurrentScope(const CurrentScope&) = delete;
  CurrentScope& operator=(const CurrentScope&) = delete;

 private:
  BytecodeGenerator* generator_;
  Scope* outer_scope_;
};

class V8_NODISCARD BytecodeGenerator::MultipleEntryBlockContextScope {
 public:
  MultipleEntryBlockContextScope(BytecodeGenerator* generator, Scope* scope)
      : generator_(generator), scope_(scope), is_in_scope_(false) {
    if (scope) {
      inner_context_ = generator->register_allocator()->NewRegister();
      outer_context_ = generator->register_allocator()->NewRegister();
      generator->BuildNewLocalBlockContext(scope_);
      generator->builder()->StoreAccumulatorInRegister(inner_context_);
    }
  }

  void SetEnteredIf(bool condition) {
    RegisterAllocationScope register_scope(generator_);
    if (condition && scope_ != nullptr && !is_in_scope_) {
      EnterScope();
    } else if (!condition && is_in_scope_) {
      ExitScope();
    }
  }

  ~MultipleEntryBlockContextScope() { DCHECK(!is_in_scope_); }

  MultipleEntryBlockContextScope(const MultipleEntryBlockContextScope&) =
      delete;
  MultipleEntryBlockContextScope& operator=(
      const MultipleEntryBlockContextScope&) = delete;

 private:
  void EnterScope() {
    DCHECK(inner_context_.is_valid());
    DCHECK(outer_context_.is_valid());
    DCHECK(!is_in_scope_);
    generator_->builder()->LoadAccumulatorWithRegister(inner_context_);
    current_scope_.emplace(generator_, scope_);
    context_scope_.emplace(generator_, scope_, outer_context_);
    is_in_scope_ = true;
  }

  void ExitScope() {
    DCHECK(inner_context_.is_valid());
    DCHECK(outer_context_.is_valid());
    DCHECK(is_in_scope_);
    context_scope_ = std::nullopt;
    current_scope_ = std::nullopt;
    is_in_scope_ = false;
  }

  BytecodeGenerator* generator_;
  Scope* scope_;
  Register inner_context_;
  Register outer_context_;
  bool is_in_scope_;
  std::optional<CurrentScope> current_scope_;
  std::optional<ContextScope> context_scope_;
};

class BytecodeGenerator::FeedbackSlotCache : public ZoneObject {
 public:
  enum class SlotKind {
    kStoreGlobalSloppy,
    kStoreGlobalStrict,
    kSetNamedStrict,
    kSetNamedSloppy,
    kLoadProperty,
    kLoadSuperProperty,
    kLoadGlobalNotInsideTypeof,
    kLoadGlobalInsideTypeof,
    kClosureFeedbackCell
  };

  explicit FeedbackSlotCache(Zone* zone) : map_(zone) {}

  void Put(SlotKind slot_kind, Variable* variable, int slot_index) {
    PutImpl(slot_kind, 0, variable, slot_index);
  }
  void Put(SlotKind slot_kind, AstNode* node, int slot_index) {
    PutImpl(slot_kind, 0, node, slot_index);
  }
  void Put(SlotKind slot_kind, int variable_index, const AstRawString* name,
           int slot_index) {
    PutImpl(slot_kind, variable_index, name, slot_index);
  }
  void Put(SlotKind slot_kind, const AstRawString* name, int slot_index) {
    PutImpl(slot_kind, 0, name, slot_index);
  }

  int Get(SlotKind slot_kind, Variable* variable) const {
    return GetImpl(slot_kind, 0, variable);
  }
  int Get(SlotKind slot_kind, AstNode* node) const {
    return GetImpl(slot_kind, 0, node);
  }
  int Get(SlotKind slot_kind, int variable_index,
          const AstRawString* name) const {
    return GetImpl(slot_kind, variable_index, name);
  }
  int Get(SlotKind slot_kind, const AstRawString* name) const {
    return GetImpl(slot_kind, 0, name);
  }

 private:
  using Key = std::tuple<SlotKind, int, const void*>;

  void PutImpl(SlotKind slot_kind, int index, const void* node,
               int slot_index) {
    Key key = std::make_tuple(slot_kind, index, node);
    auto entry = std::make_pair(key, slot_index);
    map_.insert(entry);
  }

  int GetImpl(SlotKind slot_kind, int index, const void* node) const {
    Key key = std::make_tuple(slot_kind, index, node);
    auto iter = map_.find(key);
    if (iter != map_.end()) {
      return iter->second;
    }
    return -1;
  }

  ZoneMap<Key, int> map_;
};

// Scoped class to help elide hole checks within a conditionally executed basic
// block. Each conditionally executed basic block must have a scope to emit
// hole checks correctly.
//
// The duration of the scope must correspond to a basic block. Numbered
// Variables (see Variable::HoleCheckBitmap) are remembered in the bitmap when
// the first hole check is emitted. Subsequent hole checks are elided.
//
// On scope exit, the hole check state at construction time is restored.
class V8_NODISCARD BytecodeGenerator::HoleCheckElisionScope {
 public:
  explicit HoleCheckElisionScope(BytecodeGenerator* bytecode_generator)
      : HoleCheckElisionScope(&bytecode_generator->hole_check_bitmap_) {}

  ~HoleCheckElisionScope() { *bitmap_ = prev_bitmap_value_; }

 protected:
  explicit HoleCheckElisionScope(Variable::HoleCheckBitmap* bitmap)
      : bitmap_(bitmap), prev_bitmap_value_(*bitmap) {}

  Variable::HoleCheckBitmap* bitmap_;
  Variable::HoleCheckBitmap prev_bitmap_value_;
};

// Scoped class to help elide hole checks within control flow that branch and
// merge.
//
// Each such control flow construct (e.g., if-else, ternary expressions) must
// have a scope to emit hole checks correctly. Additionally, each branch must
// have a Branch.
//
// The Merge or MergeIf method must be called to merge variables that have been
// hole-checked along every branch are marked as no longer needing a hole check.
//
// Example:
//
//   HoleCheckElisionMergeScope merge_elider(this);
//   {
//      HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
//      Visit(then_branch);
//   }
//   {
//      HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
//      Visit(else_branch);
//   }
//   merge_elider.Merge();
//
// Conversely, it is incorrect to use this class for control flow constructs
// that do not merge (e.g., if without else). HoleCheckElisionScope should be
// used for those cases.
class V8_NODISCARD BytecodeGenerator::HoleCheckElisionMergeScope final {
 public:
  explicit HoleCheckElisionMergeScope(BytecodeGenerator* bytecode_generator)
      : bitmap_(&bytecode_generator->hole_check_bitmap_) {}

  ~HoleCheckElisionMergeScope() {
    // Did you forget to call Merge or MergeIf?
    DCHECK(merge_called_);
  }

  void Merge() {
    DCHECK_NE(UINT64_MAX, merge_value_);
    *bitmap_ = merge_value_;
#ifdef DEBUG
    merge_called_ = true;
#endif
  }

  void MergeIf(bool cond) {
    if (cond) Merge();
#ifdef DEBUG
    merge_called_ = true;
#endif
  }

  class V8_NODISCARD Branch final : public HoleCheckElisionScope {
   public:
    explicit Branch(HoleCheckElisionMergeScope& merge_into)
        : HoleCheckElisionScope(merge_into.bitmap_),
          merge_into_bitmap_(&merge_into.merge_value_) {}

    ~Branch() { *merge_into_bitmap_ &= *bitmap_; }

   private:
    Variable::HoleCheckBitmap* merge_into_bitmap_;
  };

 private:
  Variable::HoleCheckBitmap* bitmap_;
  Variable::HoleCheckBitmap merge_value_ = UINT64_MAX;

#ifdef DEBUG
  bool merge_called_ = false;
#endif
};

class BytecodeGenerator::IteratorRecord final {
 public:
  IteratorRecord(Register object_register, Register next_register,
                 IteratorType type = IteratorType::kNormal)
      : type_(type), object_(object_register), next_(next_register) {
    DCHECK(object_.is_valid() && next_.is_valid());
  }

  inline IteratorType type() const { return type_; }
  inline Register object() const { return object_; }
  inline Register next() const { return next_; }

 private:
  IteratorType type_;
  Register object_;
  Register next_;
};

class V8_NODISCARD BytecodeGenerator::OptionalChainNullLabelScope final {
 public:
  explicit OptionalChainNullLabelScope(BytecodeGenerator* bytecode_generator)
      : bytecode_generator_(bytecode_generator),
        labels_(bytecode_generator->zone()) {
    prev_ = bytecode_generator_->optional_chaining_null_labels_;
    bytecode_generator_->optional_chaining_null_labels_ = &labels_;
  }

  ~OptionalChainNullLabelScope() {
    bytecode_generator_->optional_chaining_null_labels_ = prev_;
  }

  BytecodeLabels* labels() { return &labels_; }

 private:
  BytecodeGenerator* bytecode_generator_;
  BytecodeLabels labels_;
  BytecodeLabels* prev_;
};

// LoopScope delimits the scope of {loop}, from its header to its final jump.
// It should be constructed iff a (conceptual) back edge should be produced. In
// the case of creating a LoopBuilder but never emitting the loop, it is valid
// to skip the creation of LoopScope.
class V8_NODISCARD BytecodeGenerator::LoopScope final {
 public:
  explicit LoopScope(BytecodeGenerator* bytecode_generator, LoopBuilder* loop)
      : bytecode_generator_(bytecode_generator),
        parent_loop_scope_(bytecode_generator_->current_loop_scope()),
        loop_builder_(loop) {
    loop_builder_->LoopHeader();
    bytecode_generator_->set_current_loop_scope(this);
    bytecode_generator_->loop_depth_++;
  }

  ~LoopScope() {
    bytecode_generator_->loop_depth_--;
    bytecode_generator_->set_current_loop_scope(parent_loop_scope_);
    DCHECK_GE(bytecode_generator_->loop_depth_, 0);
    loop_builder_->JumpToHeader(
        bytecode_generator_->loop_depth_,
        parent_loop_scope_ ? parent_loop_scope_->loop_builder_ : nullptr);
  }

 private:
  BytecodeGenerator* const bytecode_generator_;
  LoopScope* const parent_loop_scope_;
  LoopBuilder* const loop_builder_;
};

class V8_NODISCARD BytecodeGenerator::ForInScope final {
 public:
  explicit ForInScope(BytecodeGenerator* bytecode_generator,
                      ForInStatement* stmt, Register enum_index,
                      Register cache_type)
      : bytecode_generator_(bytecode_generator),
        parent_for_in_scope_(bytecode_generator_->current_for_in_scope()),
        each_var_(nullptr),
        enum_index_(enum_index),
        cache_type_(cache_type) {
    if (v8_flags.enable_enumerated_keyed_access_bytecode) {
      Expression* each = stmt->each();
      if (each->IsVariableProxy()) {
        Variable* each_var = each->AsVariableProxy()->var();
        if (each_var->IsStackLocal()) {
          each_var_ = each_var;
          bytecode_generator_->SetVariableInRegister(
              each_var_,
              bytecode_generator_->builder()->Local(each_var_->index()));
        }
      }
      bytecode_generator_->set_current_for_in_scope(this);
    }
  }

  ~ForInScope() {
    if (v8_flags.enable_enumerated_keyed_access_bytecode) {
      bytecode_generator_->set_current_for_in_scope(parent_for_in_scope_);
    }
  }

  // Get corresponding {ForInScope} for a given {each} variable.
  ForInScope* GetForInScope(Variable* each) {
    DCHECK(v8_flags.enable_enumerated_keyed_access_bytecode);
    ForInScope* scope = this;
    do {
      if (each == scope->each_var_) break;
      scope = scope->parent_for_in_scope_;
    } while (scope != nullptr);
    return scope;
  }

  Register enum_index() { return enum_index_; }
  Register cache_type() { return cache_type_; }

 private:
  BytecodeGenerator* const bytecode_generator_;
  ForInScope* const parent_for_in_scope_;
  Variable* each_var_;
  Register enum_index_;
  Register cache_type_;
};

class V8_NODISCARD BytecodeGenerator::DisposablesStackScope final {
 public:
  explicit DisposablesStackScope(BytecodeGenerator* bytecode_generator)
      : bytecode_generator_(bytecode_generator),
        prev_disposables_stack_(
            bytecode_generator_->current_disposables_stack()) {
    bytecode_generator_->current_disposables_stack_ =
        bytecode_generator->register_allocator()->NewRegister();
    bytecode_generator->builder()->CallRuntime(
        Runtime::kInitializeDisposableStack);
    bytecode_generator->builder()->StoreAccumulatorInRegister(
        bytecode_generator_->current_disposables_stack_);
  }

  ~DisposablesStackScope() {
    bytecode_generator_->set_current_disposables_stack(prev_disposables_stack_);
  }

 private:
  BytecodeGenerator* const bytecode_generator_;
  Register prev_disposables_stack_;
};

namespace {

template <typename PropertyT>
struct Accessors : public ZoneObject {
  Accessors() : getter(nullptr), setter(nullptr) {}
  PropertyT* getter;
  PropertyT* setter;
};

// A map from property names to getter/setter pairs allocated in the zone that
// also provides a way of accessing the pairs in the order they were first
// added so that the generated bytecode is always the same.
template <typename PropertyT>
class AccessorTable
    : public base::TemplateHashMap<Literal, Accessors<PropertyT>,
                                   bool (*)(void*, void*),
                                   ZoneAllocationPolicy> {
 public:
  explicit AccessorTable(Zone* zone)
      : base::TemplateHashMap<Literal, Accessors<PropertyT>,
                              bool (*)(void*, void*), ZoneAllocationPolicy>(
            Literal::Match, ZoneAllocationPolicy(zone)),
        zone_(zone) {}

  Accessors<PropertyT>* LookupOrInsert(Literal* key) {
    auto it = this->find(key, true);
    if (it->second == nullptr) {
      it->second = zone_->New<Accessors<PropertyT>>();
      ordered_accessors_.push_back({key, it->second});
    }
    return it->second;
  }

  const std::vector<std::pair<Literal*, Accessors<PropertyT>*>>&
  ordered_accessors() {
    return ordered_accessors_;
  }

 private:
  std::vector<std::pair<Literal*, Accessors<PropertyT>*>> ordered_accessors_;

  Zone* zone_;
};

}  // namespace

#ifdef DEBUG

static bool IsInEagerLiterals(
    FunctionLiteral* literal,
    const std::vector<FunctionLiteral*>& eager_literals) {
  for (FunctionLiteral* eager_literal : eager_literals) {
    if (literal == eager_literal) return true;
  }
  return false;
}

#endif  // DEBUG

BytecodeGenerator::BytecodeGenerator(
    LocalIsolate* local_isolate, Zone* compile_zone,
    UnoptimizedCompilationInfo* info,
    const AstStringConstants* ast_string_constants,
    std::vector<FunctionLiteral*>* eager_inner_literals, Handle<Script> script)
    : local_isolate_(local_isolate),
      zone_(compile_zone),
      builder_(zone(), info->num_parameters_including_this(),
               info->scope()->num_stack_slots(), info->feedback_vector_spec(),
               info->SourcePositionRecordingMode()),
      info_(info),
      ast_string_constants_(ast_string_constants),
      closure_scope_(info->scope()),
      current_scope_(info->scope()),
      eager_inner_literals_(eager_inner_literals),
      script_(script),
      feedback_slot_cache_(zone()->New<FeedbackSlotCache>(zone())),
      top_level_builder_(zone()->New<TopLevelDeclarationsBuilder>()),
      block_coverage_builder_(nullptr),
      function_literals_(0, zone()),
      native_function_literals_(0, zone()),
      object_literals_(0, zone()),
      array_literals_(0, zone()),
      class_literals_(0, zone()),
      template_objects_(0, zone()),
      vars_in_hole_check_bitmap_(0, zone()),
      execution_control_(nullptr),
      execution_context_(nullptr),
      execution_result_(nullptr),
      incoming_new_target_or_generator_(),
      current_disposables_stack_(),
      optional_chaining_null_labels_(nullptr),
      dummy_feedback_slot_(feedback_spec(), FeedbackSlotKind::kCompareOp),
      generator_jump_table_(nullptr),
      suspend_count_(0),
      loop_depth_(0),
      hole_check_bitmap_(0),
      current_loop_scope_(nullptr),
      current_for_in_scope_(nullptr),
      catch_prediction_(HandlerTable::UNCAUGHT) {
  DCHECK_EQ(closure_scope(), closure_scope()->GetClosureScope());
  if (info->has_source_range_map()) {
    block_coverage_builder_ = zone()->New<BlockCoverageBuilder>(
        zone(), builder(), info->source_range_map());
  }
}

namespace {

template <typename Isolate>
struct NullContextScopeHelper;

template <>
struct NullContextScopeHelper<Isolate> {
  using Type = NullContextScope;
};

template <>
struct NullContextScopeHelper<LocalIsolate> {
  class V8_NODISCARD DummyNullContextScope {
   public:
    explicit DummyNullContextScope(LocalIsolate*) {}
  };
  using Type = DummyNullContextScope;
};

template <typename Isolate>
using NullContextScopeFor = typename NullContextScopeHelper<Isolate>::Type;

}  // namespace

template <typename IsolateT>
Handle<BytecodeArray> BytecodeGenerator::FinalizeBytecode(
    IsolateT* isolate, Handle<Script> script) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
#ifdef DEBUG
  // Unoptimized compilation should be context-independent. Verify that we don't
  // access the native context by nulling it out during finalization.
  NullContextScopeFor<IsolateT> null_context_scope(isolate);
#endif

  AllocateDeferredConstants(isolate, script);

  if (block_coverage_builder_) {
    Handle<CoverageInfo> coverage_info =
        isolate->factory()->NewCoverageInfo(block_coverage_builder_->slots());
    info()->set_coverage_info(coverage_info);
    if (v8_flags.trace_block_coverage) {
      StdoutStream os;
      coverage_info->CoverageInfoPrint(os, info()->literal()->GetDebugName());
    }
  }

  if (HasStackOverflow()) return Handle<BytecodeArray>();
  Handle<BytecodeArray> bytecode_array = builder()->ToBytecodeArray(isolate);

  if (incoming_new_target_or_generator_.is_valid()) {
    bytecode_array->set_incoming_new_target_or_generator_register(
        incoming_new_target_or_generator_);
  }

  return bytecode_array;
}

template Handle<BytecodeArray> BytecodeGenerator::FinalizeBytecode(
    Isolate* isolate, Handle<Script> script);
template Handle<BytecodeArray> BytecodeGenerator::FinalizeBytecode(
    LocalIsolate* isolate, Handle<Script> script);

template <typename IsolateT>
Handle<TrustedByteArray> BytecodeGenerator::FinalizeSourcePositionTable(
    IsolateT* isolate) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
#ifdef DEBUG
  // Unoptimized compilation should be context-independent. Verify that we don't
  // access the native context by nulling it out during finalization.
  NullContextScopeFor<IsolateT> null_context_scope(isolate);
#endif

  Handle<TrustedByteArray> source_position_table =
      builder()->ToSourcePositionTable(isolate);

  LOG_CODE_EVENT(isolate,
                 CodeLinePosInfoRecordEvent(
                     info_->bytecode_array()->GetFirstBytecodeAddress(),
                     *source_position_table, JitCodeEvent::BYTE_CODE));

  return source_position_table;
}

template Handle<TrustedByteArray>
BytecodeGenerator::FinalizeSourcePositionTable(Isolate* isolate);
template Handle<TrustedByteArray>
BytecodeGenerator::FinalizeSourcePositionTable(LocalIsolate* isolate);

#ifdef DEBUG
int BytecodeGenerator::CheckBytecodeMatches(Tagged<BytecodeArray> bytecode) {
  return builder()->CheckBytecodeMatches(bytecode);
}
#endif

template <typename IsolateT>
void BytecodeGenerator::AllocateDeferredConstants(IsolateT* isolate,
                                                  Handle<Script> script) {
  if (top_level_builder()->has_top_level_declaration()) {
    // Build global declaration pair array.
    Handle<FixedArray> declarations = top_level_builder()->AllocateDeclarations(
        info(), this, script, isolate);
    if (declarations.is_null()) return SetStackOverflow();
    builder()->SetDeferredConstantPoolEntry(
        top_level_builder()->constant_pool_entry(), declarations);
  }

  // Find or build shared function infos.
  for (std::pair<FunctionLiteral*, size_t> literal : function_literals_) {
    FunctionLiteral* expr = literal.first;
    DirectHandle<SharedFunctionInfo> shared_info =
        Compiler::GetSharedFunctionInfo(expr, script, isolate);
    if (shared_info.is_null()) return SetStackOverflow();
    builder()->SetDeferredConstantPoolEntry(
        literal.second, indirect_handle(shared_info, isolate));
  }

  // Find or build shared function infos for the native function templates.
  for (std::pair<NativeFunctionLiteral*, size_t> literal :
       native_function_literals_) {
    // This should only happen for main-thread compilations.
    DCHECK((std::is_same<Isolate, v8::internal::Isolate>::value));

    NativeFunctionLiteral* expr = literal.first;
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);

    // Compute the function template for the native function.
    v8::Local<v8::FunctionTemplate> info =
        expr->extension()->GetNativeFunctionTemplate(
            v8_isolate, Utils::ToLocal(expr->name()));
    DCHECK(!info.IsEmpty());

    Handle<SharedFunctionInfo> shared_info =
        FunctionTemplateInfo::GetOrCreateSharedFunctionInfo(
            isolate, Utils::OpenHandle(*info), expr->name());
    DCHECK(!shared_info.is_null());
    builder()->SetDeferredConstantPoolEntry(literal.second, shared_info);
  }

  // Build object literal constant properties
  for (std::pair<ObjectLiteralBoilerplateBuilder*, size_t> literal :
       object_literals_) {
    ObjectLiteralBoilerplateBuilder* object_literal_builder = literal.first;
    if (object_literal_builder->properties_count() > 0) {
      // If constant properties is an empty fixed array, we've already added it
      // to the constant pool when visiting the object literal.
      Handle<ObjectBoilerplateDescription> constant_properties =
          object_literal_builder->GetOrBuildBoilerplateDescription(isolate);

      builder()->SetDeferredConstantPoolEntry(literal.second,
                                              constant_properties);
    }
  }

  // Build array literal constant elements
  for (std::pair<ArrayLiteralBoilerplateBuilder*, size_t> literal :
       array_literals_) {
    ArrayLiteralBoilerplateBuilder* array_literal_builder = literal.first;
    Handle<ArrayBoilerplateDescription> constant_elements =
        array_literal_builder->GetOrBuildBoilerplateDescription(isolate);
    builder()->SetDeferredConstantPoolEntry(literal.second, constant_elements);
  }

  // Build class literal boilerplates.
  for (std::pair<ClassLiteral*, size_t> literal : class_literals_) {
    ClassLiteral* class_literal = literal.first;
    Handle<ClassBoilerplate> class_boilerplate =
        ClassBoilerplate::New(isolate, class_literal, AllocationType::kOld);
    builder()->SetDeferredConstantPoolEntry(literal.second, class_boilerplate);
  }

  // Build template literals.
  for (std::pair<GetTemplateObject*, size_t> literal : template_objects_) {
    GetTemplateObject* get_template_object = literal.first;
    Handle<TemplateObjectDescription> description =
        get_template_object->GetOrBuildDescription(isolate);
    builder()->SetDeferredConstantPoolEntry(literal.second, description);
  }
}

template void BytecodeGenerator::AllocateDeferredConstants(
    Isolate* isolate, Handle<Script> script);
template void BytecodeGenerator::AllocateDeferredConstants(
    LocalIsolate* isolate, Handle<Script> script);

namespace {
bool NeedsContextInitialization(DeclarationScope* scope) {
  return scope->NeedsContext() && !scope->is_script_scope() &&
         !scope->is_module_scope();
}
}  // namespace

void BytecodeGenerator::GenerateBytecode(uintptr_t stack_limit) {
  InitializeAstVisitor(stack_limit);
  if (v8_flags.stress_lazy_compilation && local_isolate_->is_main_thread() &&
      !local_isolate_->AsIsolate()->bootstrapper()->IsActive()) {
    // Trigger stack overflow with 1/stress_lazy_compilation probability.
    // Do this only for the main thread compilations because querying random
    // numbers from background threads will make the random values dependent
    // on the thread scheduling and thus non-deterministic.
    stack_overflow_ = local_isolate_->fuzzer_rng()->NextInt(
                          v8_flags.stress_lazy_compilation) == 0;
  }

  // Initialize the incoming context.
  ContextScope incoming_context(this, closure_scope());

  // Initialize control scope.
  ControlScopeForTopLevel control(this);

  RegisterAllocationScope register_scope(this);

  AllocateTopLevelRegisters();

  builder()->EmitFunctionStartSourcePosition(
      info()->literal()->start_position());

  if (info()->literal()->CanSuspend()) {
    BuildGeneratorPrologue();
  }

  if (NeedsContextInitialization(closure_scope())) {
    // Push a new inner context scope for the function.
    BuildNewLocalActivationContext();
    ContextScope local_function_context(this, closure_scope());
    BuildLocalActivationContextInitialization();
    GenerateBytecodeBody();
  } else {
    GenerateBytecodeBody();
  }

  // Reset variables with hole check bitmap indices for subsequent compilations
  // in the same parsing zone.
  for (Variable* var : vars_in_hole_check_bitmap_) {
    var->ResetHoleCheckBitmapIndex();
  }

  // Check that we are not falling off the end.
  DCHECK(builder()->RemainderOfBlockIsDead());
}

void BytecodeGenerator::GenerateBytecodeBody() {
  GenerateBodyPrologue();

  if (IsBaseConstructor(function_kind())) {
    GenerateBaseConstructorBody();
  } else if (function_kind() == FunctionKind::kDerivedConstructor) {
    GenerateDerivedConstructorBody();
  } else if (IsAsyncFunction(function_kind()) ||
             IsModuleWithTopLevelAwait(function_kind())) {
    if (IsAsyncGeneratorFunction(function_kind())) {
      GenerateAsyncGeneratorFunctionBody();
    } else {
      GenerateAsyncFunctionBody();
    }
  } else {
    GenerateBodyStatements();
  }
}

void BytecodeGenerator::GenerateBodyPrologue() {
  // Build the arguments object if it is used.
  VisitArgumentsObject(closure_scope()->arguments());

  // Build rest arguments array if it is used.
  Variable* rest_parameter = closure_scope()->rest_parameter();
  VisitRestArgumentsArray(rest_parameter);

  // Build assignment to the function name or {.this_function}
  // variables if used.
  VisitThisFunctionVariable(closure_scope()->function_var());
  VisitThisFunctionVariable(closure_scope()->this_function_var());

  // Build assignment to {new.target} variable if it is used.
  VisitNewTargetVariable(closure_scope()->new_target_var());

  // Create a generator object if necessary and initialize the
  // {.generator_object} variable.
  FunctionLiteral* literal = info()->literal();
  if (IsResumableFunction(literal->kind())) {
    BuildGeneratorObjectVariableInitialization();
  }

  // Emit tracing call if requested to do so.
  if (v8_flags.trace) builder()->CallRuntime(Runtime::kTraceEnter);

  // Increment the function-scope block coverage counter.
  BuildIncrementBlockCoverageCounterIfEnabled(literal, SourceRangeKind::kBody);

  // Visit declarations within the function scope.
  if (closure_scope()->is_script_scope()) {
    VisitGlobalDeclarations(closure_scope()->declarations());
  } else if (closure_scope()->is_module_scope()) {
    VisitModuleDeclarations(closure_scope()->declarations());
  } else {
    VisitDeclarations(closure_scope()->declarations());
  }

  // Emit initializing assignments for module namespace imports (if any).
  VisitModuleNamespaceImports();
}

void BytecodeGenerator::GenerateBaseConstructorBody() {
  DCHECK(IsBaseConstructor(function_kind()));

  FunctionLiteral* literal = info()->literal();

  // The derived constructor case is handled in VisitCallSuper.
  if (literal->class_scope_has_private_brand()) {
    ClassScope* scope = info()->scope()->outer_scope()->AsClassScope();
    DCHECK_NOT_NULL(scope->brand());
    BuildPrivateBrandInitialization(builder()->Receiver(), scope->brand());
  }

  if (literal->requires_instance_members_initializer()) {
    BuildInstanceMemberInitialization(Register::function_closure(),
                                      builder()->Receiver());
  }

  GenerateBodyStatements();
}

void BytecodeGenerator::GenerateDerivedConstructorBody() {
  DCHECK_EQ(FunctionKind::kDerivedConstructor, function_kind());

  FunctionLiteral* literal = info()->literal();

  // Per spec, derived constructors can only return undefined or an object;
  // other primitives trigger an exception in ConstructStub.
  //
  // Since the receiver is popped by the callee, derived constructors return
  // <this> if the original return value was undefined.
  //
  // Also per spec, this return value check is done after all user code (e.g.,
  // finally blocks) are executed. For example, the following code does not
  // throw.
  //
  //   class C extends class {} {
  //     constructor() {
  //       try { throw 42; }
  //       catch(e) { return; }
  //       finally { super(); }
  //     }
  //   }
  //   new C();
  //
  // This check is implemented by jumping to the check instead of emitting a
  // return bytecode in-place inside derived constructors.
  //
  // Note that default derived constructors do not need this check as they
  // just forward a super call.

  BytecodeLabels check_return_value(zone());
  Register result = register_allocator()->NewRegister();
  ControlScopeForDerivedConstructor control(this, result, &check_return_value);

  {
    HoleCheckElisionScope elider(this);
    GenerateBodyStatementsWithoutImplicitFinalReturn();
  }

  if (check_return_value.empty()) {
    if (!builder()->RemainderOfBlockIsDead()) {
      BuildThisVariableLoad();
      BuildReturn(literal->return_position());
    }
  } else {
    BytecodeLabels return_this(zone());

    if (!builder()->RemainderOfBlockIsDead()) {
      builder()->Jump(return_this.New());
    }

    check_return_value.Bind(builder());
    builder()->LoadAccumulatorWithRegister(result);
    builder()->JumpIfUndefined(return_this.New());
    BuildReturn(literal->return_position());

    {
      return_this.Bind(builder());
      BuildThisVariableLoad();
      BuildReturn(literal->return_position());
    }
  }
}

void BytecodeGenerator::GenerateAsyncFunctionBody() {
  DCHECK((IsAsyncFunction(function_kind()) &&
          !IsAsyncGeneratorFunction(function_kind())) ||
         IsModuleWithTopLevelAwait(function_kind()));

  // Async functions always return promises. Return values fulfill that promise,
  // while synchronously thrown exceptions reject that promise. This is handled
  // by surrounding the body statements in a try-catch block as follows:
  //
  // try {
  //   <inner_block>
  // } catch (.catch) {
  //   return %_AsyncFunctionReject(.generator_object, .catch);
  // }

  FunctionLiteral* literal = info()->literal();

  HandlerTable::CatchPrediction outer_catch_prediction = catch_prediction();
  // When compiling a REPL script, use UNCAUGHT_ASYNC_AWAIT to preserve the
  // exception so DevTools can inspect it.
  set_catch_prediction(literal->scope()->is_repl_mode_scope()
                           ? HandlerTable::UNCAUGHT_ASYNC_AWAIT
                           : HandlerTable::ASYNC_AWAIT);

  BuildTryCatch(
      [&]() {
        GenerateBodyStatements();
        set_catch_prediction(outer_catch_prediction);
      },
      [&](Register context) {
        RegisterList args = register_allocator()->NewRegisterList(2);
        builder()
            ->MoveRegister(generator_object(), args[0])
            .StoreAccumulatorInRegister(args[1])  // exception
            .CallRuntime(Runtime::kInlineAsyncFunctionReject, args);
        // TODO(358404372): Should this return have a statement position?
        // Without one it is not possible to apply a debugger breakpoint.
        BuildReturn(kNoSourcePosition);
      },
      catch_prediction());
}

void BytecodeGenerator::GenerateAsyncGeneratorFunctionBody() {
  DCHECK(IsAsyncGeneratorFunction(function_kind()));
  set_catch_prediction(HandlerTable::ASYNC_AWAIT);

  // For ES2017 Async Generators, we produce:
  //
  // try {
  //   InitialYield;
  //   ...body...;
  // } catch (.catch) {
  //   %AsyncGeneratorReject(generator, .catch);
  // } finally {
  //   %_GeneratorC
```