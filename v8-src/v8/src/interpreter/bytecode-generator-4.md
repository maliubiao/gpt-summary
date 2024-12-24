Response: The user wants a summary of the C++ source code file `v8/src/interpreter/bytecode-generator.cc`.
This file seems to be responsible for generating bytecode from an Abstract Syntax Tree (AST) for the V8 JavaScript engine's interpreter.

Here's a breakdown of the code's functionality:

1. **Handling `super()` calls:**  The code contains logic for generating bytecode for `super()` calls in constructors, including optimizations for default constructors and handling private brand initialization.
2. **Generating `new` calls:** It handles the generation of bytecode for `new` expressions, including cases with spread syntax. It also handles `Reflect.construct`.
3. **Generating runtime calls:** The code generates bytecode to call built-in runtime functions.
4. **Implementing unary operators:** It generates bytecode for unary operations like `void`, `typeof`, `!`, `delete`, `+`, `-`, `~`.
5. **Implementing `delete` operator:**  It handles the `delete` operator, including different cases like deleting properties, global variables, and super properties.
6. **Implementing count operations:** It generates bytecode for increment/decrement operators (`++`, `--`).
7. **Implementing binary and n-ary operations:** It handles bytecode generation for various binary and n-ary operations (comma, logical OR/AND/Nullish, arithmetic).
8. **Optimizing comparisons:** It has specific logic for optimizing comparisons with literals (null, undefined, booleans) and `typeof`.
9. **Generating `in` and `instanceof` operators:** It generates bytecode for these operators.
10. **Generating template literals:**  The code handles the generation of bytecode for template literals.
11. **Handling `this` and `super`:**  It generates bytecode for `this` and `super` expressions.
12. **Implementing logical operators:**  It implements short-circuiting behavior for logical OR, AND, and nullish coalescing operators.
13. **Creating contexts:** The code generates bytecode for creating different types of execution contexts (function, eval, block, with, catch).
14. **Initializing contexts:** It includes logic for initializing local activation contexts with parameters and the receiver.
15. **Handling special variables:** It deals with the creation and initialization of special variables like `arguments`, rest parameters, `this function`, and `new.target`.
16. **Generating iterator-related code:** The code includes logic for getting iterators (`@@iterator`, `@@asyncIterator`), calling `next()`, and closing iterators.
17. **Code coverage:** It includes mechanisms for generating code to track block coverage for testing purposes.
18. **Helper functions for visiting expressions:** It defines helper functions like `VisitForAccumulatorValue`, `VisitForEffect`, `VisitForRegisterValue`, and `VisitForTest` to recursively traverse the AST and generate bytecode.

Relationship to JavaScript: This code directly translates JavaScript language constructs into lower-level bytecode instructions that the V8 interpreter can execute. Each section of the C++ code corresponds to specific features or operators in JavaScript.

Example in JavaScript:

```javascript
// Example demonstrating super() call and instance member initialization
class Base {
  constructor() {
    this.baseProperty = 1;
  }
}

class Derived extends Base {
  constructor() {
    super(); // Calls the super constructor
    this.derivedProperty = 2; // Instance member initialization
  }
}

// Example demonstrating the delete operator
const obj = { a: 1, b: 2 };
delete obj.a; // Deletes the 'a' property

// Example demonstrating a typeof comparison
const type = typeof obj; // Evaluates to "object"
if (typeof obj === 'object') {
  console.log("It's an object!");
}

// Example demonstrating a logical OR expression
const x = null;
const y = x || "default value"; // y will be "default value"

// Example demonstrating a template literal
const name = "World";
const greeting = `Hello, ${name}!`;
```

**Summary of Part 5:**

This part of the `bytecode-generator.cc` file focuses on generating bytecode for various JavaScript **expressions**. It covers:

- **Function calls:** Specifically, `super()` calls and optimizations related to them.
- **Object creation:**  `new` calls, including handling spread syntax and calls to `Reflect.construct`.
- **Runtime function calls:** Generating calls to internal V8 runtime functions.
- **Unary operators:**  Implementations for `void`, `typeof`, `!`, and `delete`.
- **Count operations:** Generating bytecode for pre/post increment and decrement.
- **Binary and N-ary Operations:** Implementing logic for comma, logical OR/AND/Nullish, and arithmetic operators, with specific optimizations and handling of string concatenation.
- **Template Literals:**  Generating code to construct template strings.
- **`this` and `super`:** Loading values for these keywords.
- **Logical Tests:** Implementing short-circuiting behavior for logical operators within conditional contexts.
- **Context creation:**  Generating bytecode for creating function, block, with, and catch scopes.
- **Variable initialization:**  Handling the initialization of special variables like `arguments`, rest parameters, `this function`, and `new.target`.
- **Iterator Handling:** Generating code for obtaining and interacting with iterators.
- **Code Coverage:**  Integrating mechanisms for tracking code execution for testing.

In essence, this section translates complex JavaScript expression syntax into the corresponding bytecode instructions that the V8 interpreter will understand and execute. It's a core component of the compilation pipeline, bridging the gap between human-readable JavaScript and machine-executable instructions within V8.

这是 `bytecode-generator.cc` 文件的第五部分，主要负责生成各种 **JavaScript 表达式** 的字节码。它涵盖了相当广泛的表达式类型，并且针对不同的情况进行了优化。

以下是本部分的主要功能归纳：

**1. 函数调用相关:**

* **处理 `super()` 调用:**  详细处理了构造函数中的 `super()` 调用，包括：
    * 处理显式调用和默认构造函数的情况。
    * 处理 `this` 变量的绑定。
    * 处理私有 brand 的初始化。
    * 优化默认构造函数的 `super()` 调用，避免不必要的代码生成。
    * 获取并检查父类构造函数是否合法。
* **处理 `new` 调用:**  生成 `new` 表达式的字节码，包括：
    * 处理带展开运算符 (`...`) 的 `new` 调用，对于末尾展开和非末尾展开有不同的处理方式（非末尾展开会使用 `%reflect_construct`）。
    * 调用构造函数并传递参数。
* **处理 `super()` 的参数转发:**  生成 `super(...args)` 的字节码。
* **处理 `import()` 动态导入:** 生成 `import()` 表达式的字节码。

**2. 运行时调用:**

* **生成运行时函数调用:**  将 `CallRuntime` 节点转换为调用 V8 运行时函数的字节码。

**3. 一元运算符:**

* **生成 `void` 运算符的字节码:**  计算表达式的值并丢弃，然后加载 `undefined` 到累加器。
* **生成 `typeof` 运算符的字节码:**  根据操作数的类型加载值，然后执行 `TypeOf` 字节码。对于全局变量，会进行非上下文加载。
* **生成 `!` (逻辑非) 运算符的字节码:**  根据上下文（效果、测试等）生成不同的字节码。对于 `!!` 模式进行优化。
* **生成其他一元运算符 (`+`, `-`, `~`):**  计算表达式的值，然后执行相应的一元操作字节码。
* **生成 `delete` 运算符的字节码:**  根据操作数的类型（属性、全局变量、未解析引用等）生成不同的字节码，包括：
    * 删除对象属性（包括 `super` 访问，但会抛出错误）。
    * 删除可选链的属性。
    * 删除全局变量（在非严格模式下）。
    * 删除局部变量或参数不会有效果。

**4. 计数运算符 (`++`, `--`):**

* **生成递增/递减运算符的字节码:**  处理前缀和后缀两种情况，包括：
    * 加载左侧表达式的值。
    * 对于后缀表达式，会先保存旧值。
    * 执行递增/递减操作。
    * 存储新值。
    * 对于后缀表达式，恢复旧值。
    * 针对不同类型的左侧表达式（变量、属性、super 属性、私有字段等）生成不同的存储字节码。

**5. 二元和多元运算符:**

* **处理逗号运算符 (`，`):**  依次执行所有表达式，返回最后一个表达式的值。
* **处理逻辑或运算符 (`||`):**  实现短路求值。
* **处理逻辑与运算符 (`&&`):**  实现短路求值。
* **处理空值合并运算符 (`??`):**  实现短路求值。
* **处理算术运算符 (`+`, `-`, `*`, `/`, `%`, `**`, `<<`, `>>`, `>>>`, `&`, `|`, `^`):**  计算操作数的值，然后执行相应的算术运算字节码。对于字符串拼接进行了特殊处理。
* **处理比较运算符 (`==`, `!=`, `===`, `!==`, `>`, `<`, `>=`, `<=`, `in`, `instanceof`):**  计算操作数的值，然后执行相应的比较操作字节码。对字面量比较（`null`, `undefined`, `boolean`）和 `typeof` 比较进行了优化。

**6. 模板字面量:**

* **生成模板字面量的字节码:**  处理带和不带插值的模板字符串，将带插值的模板字符串转换为字符串拼接操作。

**7. `this` 和 `super` 表达式:**

* **生成 `this` 表达式的字节码:**  加载 `this` 变量的值。
* **生成 `super` 属性引用的字节码:**  由赋值、调用、删除和属性加载等操作处理。

**8. 字面量比较优化:**

* **针对 `null` 和 `undefined` 的比较进行优化，生成 `JumpIfNil` 字节码。**
* **针对布尔字面量的严格相等比较进行优化。**
* **针对 `typeof` 比较进行优化，生成 `CompareTypeOf` 字节码。**

**9. 上下文管理:**

* **创建新的本地激活上下文 (函数或 eval):**  根据作用域的大小选择创建 `CreateEvalContext` 或 `CreateFunctionContext` 字节码，或者调用运行时函数 `kNewFunctionContext`。
* **初始化本地激活上下文:**  将接收者 (this) 和参数复制到上下文中。
* **创建新的本地块级上下文:**  生成 `CreateBlockContext` 字节码。
* **创建新的 `with` 上下文:**  生成 `CreateWithContext` 字节码。
* **创建新的 `catch` 上下文:**  生成 `CreateCatchContext` 字节码。

**10. 特殊变量处理:**

* **处理 `arguments` 对象:**  创建并赋值 `arguments` 对象。
* **处理剩余参数 (`...rest`):**  创建并赋值剩余参数数组。
* **处理 `this function` 变量:**  存储当前的闭包。
* **处理 `new.target` 变量:**  存储 `new.target` 的值。
* **处理生成器对象变量:**  在生成器函数入口处创建并初始化生成器对象。

**11. 迭代器处理:**

* **生成获取迭代器的字节码:**  根据迭代器类型（同步或异步）调用 `GetIterator` 或 `GetAsyncIteratorProperty` 字节码。
* **生成获取迭代器记录的字节码:**  获取迭代器对象和 `next` 方法。
* **生成调用迭代器 `next()` 方法的字节码:**  调用 `CallProperty` 字节码。
* **生成调用迭代器 `return()` 方法的字节码:**  用于在迭代过程中提前退出。

**12. 代码覆盖率:**

* **分配代码块覆盖率槽位:**  用于在测试中跟踪代码块的执行次数。
* **生成递增代码块覆盖率计数器的字节码。**

**13. 辅助函数:**

* 提供了各种辅助函数，如 `VisitForAccumulatorValue`、`VisitForEffect`、`VisitForRegisterValue` 和 `VisitForTest`，用于递归遍历 AST 并生成相应的字节码。

**与 JavaScript 功能的关系及示例:**

本部分代码直接对应 JavaScript 中各种表达式的语法结构。它负责将高级的 JavaScript 语法转换为 V8 虚拟机可以执行的低级字节码。

例如：

```javascript
// 对应 BuildSuperCallOptimization
class Parent {
  constructor() {}
}
class Child extends Parent {
  constructor() {
    super(); // 调用父类构造函数
  }
}

// 对应 VisitCallNew
new Date(); // 创建一个新的 Date 对象

// 对应 VisitUnaryOperation (typeof)
typeof variable; // 获取变量的类型

// 对应 VisitBinaryOperation (逻辑或)
const value = input || "default"; // 如果 input 为假值，则使用 "default"

// 对应 VisitTemplateLiteral
const name = "World";
const greeting = `Hello, ${name}!`; // 使用模板字面量
```

**总结:**

第五部分是 `bytecode-generator.cc` 中非常核心的部分，它承担着将各种 JavaScript 表达式转换为可执行字节码的关键任务。它涵盖了广泛的语法结构，并包含了针对性能的优化措施，是理解 V8 解释器如何执行 JavaScript 代码的重要组成部分。

Prompt: 
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共6部分，请归纳一下它的功能

"""
instance) {
  // Explicit calls to the super constructor using super() perform an
  // implicit binding assignment to the 'this' variable.
  //
  // Default constructors don't need have to do the assignment because
  // 'this' isn't accessed in default constructors.
  if (!IsDefaultConstructor(info()->literal()->kind())) {
    Variable* var = closure_scope()->GetReceiverScope()->receiver();
    builder()->LoadAccumulatorWithRegister(instance);
    BuildVariableAssignment(var, Token::kInit, HoleCheckMode::kRequired);
  }

  // The constructor scope always needs ScopeInfo, so we are certain that
  // the first constructor scope found in the outer scope chain is the
  // scope that we are looking for for this super() call.
  // Note that this doesn't necessarily mean that the constructor needs
  // a context, if it doesn't this would get handled specially in
  // BuildPrivateBrandInitialization().
  DeclarationScope* constructor_scope = info()->scope()->GetConstructorScope();

  // We can rely on the class_scope_has_private_brand bit to tell if the
  // constructor needs private brand initialization, and if that's
  // the case we are certain that its outer class scope requires a context to
  // keep the brand variable, so we can just get the brand variable
  // from the outer scope.
  if (constructor_scope->class_scope_has_private_brand()) {
    DCHECK(constructor_scope->outer_scope()->is_class_scope());
    ClassScope* class_scope = constructor_scope->outer_scope()->AsClassScope();
    DCHECK_NOT_NULL(class_scope->brand());
    Variable* brand = class_scope->brand();
    BuildPrivateBrandInitialization(instance, brand);
  }

  // The derived constructor has the correct bit set always, so we
  // don't emit code to load and call the initializer if not
  // required.
  //
  // For the arrow function or eval case, we always emit code to load
  // and call the initializer.
  //
  // TODO(gsathya): In the future, we could tag nested arrow functions
  // or eval with the correct bit so that we do the load conditionally
  // if required.
  if (info()->literal()->requires_instance_members_initializer() ||
      !IsDerivedConstructor(info()->literal()->kind())) {
    BuildInstanceMemberInitialization(this_function, instance);
  }
}

void BytecodeGenerator::BuildGetAndCheckSuperConstructor(
    Register this_function, Register new_target, Register constructor,
    BytecodeLabel* super_ctor_call_done) {
  bool omit_super_ctor = v8_flags.omit_default_ctors &&
                         IsDerivedConstructor(info()->literal()->kind());

  if (omit_super_ctor) {
    BuildSuperCallOptimization(this_function, new_target, constructor,
                               super_ctor_call_done);
  } else {
    builder()
        ->LoadAccumulatorWithRegister(this_function)
        .GetSuperConstructor(constructor);
  }

  // Check if the constructor is in fact a constructor.
  builder()->ThrowIfNotSuperConstructor(constructor);
}

void BytecodeGenerator::BuildSuperCallOptimization(
    Register this_function, Register new_target,
    Register constructor_then_instance, BytecodeLabel* super_ctor_call_done) {
  DCHECK(v8_flags.omit_default_ctors);
  RegisterList output = register_allocator()->NewRegisterList(2);
  builder()->FindNonDefaultConstructorOrConstruct(this_function, new_target,
                                                  output);
  builder()->MoveRegister(output[1], constructor_then_instance);
  builder()->LoadAccumulatorWithRegister(output[0]).JumpIfTrue(
      ToBooleanMode::kAlreadyBoolean, super_ctor_call_done);
}

void BytecodeGenerator::VisitCallNew(CallNew* expr) {
  RegisterList args = register_allocator()->NewGrowableRegisterList();

  // Load the constructor. It's in the first register in args for ease of
  // calling %reflect_construct if we have a non-final spread. For all other
  // cases it is popped before emitting the construct below.
  VisitAndPushIntoRegisterList(expr->expression(), &args);

  // We compile the new differently depending on the presence of spreads and
  // their positions.
  //
  // If there is only one spread and it is the final argument, there is a
  // special ConstructWithSpread bytecode.
  //
  // If there is a non-final spread, we rewrite calls like
  //     new ctor(1, ...x, 2)
  // to
  //     %reflect_construct(ctor, [1, ...x, 2])
  const CallNew::SpreadPosition spread_position = expr->spread_position();

  if (spread_position == CallNew::kHasNonFinalSpread) {
    BuildCreateArrayLiteral(expr->arguments(), nullptr);
    builder()->SetExpressionPosition(expr);
    builder()
        ->StoreAccumulatorInRegister(
            register_allocator()->GrowRegisterList(&args))
        .CallJSRuntime(Context::REFLECT_CONSTRUCT_INDEX, args);
    return;
  }

  Register constructor = args.first_register();
  args = args.PopLeft();
  VisitArguments(expr->arguments(), &args);

  // The accumulator holds new target which is the same as the
  // constructor for CallNew.
  builder()->SetExpressionPosition(expr);
  builder()->LoadAccumulatorWithRegister(constructor);

  int feedback_slot_index = feedback_index(feedback_spec()->AddCallICSlot());
  if (spread_position == CallNew::kHasFinalSpread) {
    builder()->ConstructWithSpread(constructor, args, feedback_slot_index);
  } else {
    DCHECK_EQ(spread_position, CallNew::kNoSpread);
    builder()->Construct(constructor, args, feedback_slot_index);
  }
}

void BytecodeGenerator::VisitSuperCallForwardArgs(SuperCallForwardArgs* expr) {
  RegisterAllocationScope register_scope(this);

  SuperCallReference* super = expr->expression();
  Register this_function = VisitForRegisterValue(super->this_function_var());
  Register new_target = VisitForRegisterValue(super->new_target_var());

  // This register initially holds the constructor, then the instance.
  Register constructor_then_instance = register_allocator()->NewRegister();

  BytecodeLabel super_ctor_call_done;

  {
    const Register& constructor = constructor_then_instance;
    BuildGetAndCheckSuperConstructor(this_function, new_target, constructor,
                                     &super_ctor_call_done);

    builder()->LoadAccumulatorWithRegister(new_target);
    builder()->SetExpressionPosition(expr);
    int feedback_slot_index = feedback_index(feedback_spec()->AddCallICSlot());

    builder()->ConstructForwardAllArgs(constructor, feedback_slot_index);
  }

  // From here onwards, constructor_then_instance holds the instance.
  const Register& instance = constructor_then_instance;
  builder()->StoreAccumulatorInRegister(instance);
  builder()->Bind(&super_ctor_call_done);

  BuildInstanceInitializationAfterSuperCall(this_function, instance);
  builder()->LoadAccumulatorWithRegister(instance);
}

void BytecodeGenerator::VisitCallRuntime(CallRuntime* expr) {
  // Evaluate all arguments to the runtime call.
  RegisterList args = register_allocator()->NewGrowableRegisterList();
  VisitArguments(expr->arguments(), &args);
  Runtime::FunctionId function_id = expr->function()->function_id;
  builder()->CallRuntime(function_id, args);
}

void BytecodeGenerator::VisitVoid(UnaryOperation* expr) {
  VisitForEffect(expr->expression());
  builder()->LoadUndefined();
}

void BytecodeGenerator::VisitForTypeOfValue(Expression* expr) {
  if (expr->IsVariableProxy()) {
    // Typeof does not throw a reference error on global variables, hence we
    // perform a non-contextual load in case the operand is a variable proxy.
    VariableProxy* proxy = expr->AsVariableProxy();
    BuildVariableLoadForAccumulatorValue(proxy->var(), proxy->hole_check_mode(),
                                         TypeofMode::kInside);
  } else {
    VisitForAccumulatorValue(expr);
  }
}

void BytecodeGenerator::VisitTypeOf(UnaryOperation* expr) {
  VisitForTypeOfValue(expr->expression());
  builder()->TypeOf(feedback_index(feedback_spec()->AddTypeOfSlot()));
  execution_result()->SetResultIsInternalizedString();
}

void BytecodeGenerator::VisitNot(UnaryOperation* expr) {
  if (execution_result()->IsEffect()) {
    VisitForEffect(expr->expression());
  } else if (execution_result()->IsTest()) {
    // No actual logical negation happening, we just swap the control flow, by
    // swapping the target labels and the fallthrough branch, and visit in the
    // same test result context.
    TestResultScope* test_result = execution_result()->AsTest();
    test_result->InvertControlFlow();
    VisitInSameTestExecutionScope(expr->expression());
  } else {
    UnaryOperation* unary_op = expr->expression()->AsUnaryOperation();
    if (unary_op && unary_op->op() == Token::kNot) {
      // Shortcut repeated nots, to capture the `!!foo` pattern for converting
      // expressions to booleans.
      TypeHint type_hint = VisitForAccumulatorValue(unary_op->expression());
      builder()->ToBoolean(ToBooleanModeFromTypeHint(type_hint));
    } else {
      TypeHint type_hint = VisitForAccumulatorValue(expr->expression());
      builder()->LogicalNot(ToBooleanModeFromTypeHint(type_hint));
    }
    // Always returns a boolean value.
    execution_result()->SetResultIsBoolean();
  }
}

void BytecodeGenerator::VisitUnaryOperation(UnaryOperation* expr) {
  switch (expr->op()) {
    case Token::kNot:
      VisitNot(expr);
      break;
    case Token::kTypeOf:
      VisitTypeOf(expr);
      break;
    case Token::kVoid:
      VisitVoid(expr);
      break;
    case Token::kDelete:
      VisitDelete(expr);
      break;
    case Token::kAdd:
    case Token::kSub:
    case Token::kBitNot:
      VisitForAccumulatorValue(expr->expression());
      builder()->SetExpressionPosition(expr);
      builder()->UnaryOperation(
          expr->op(), feedback_index(feedback_spec()->AddBinaryOpICSlot()));
      break;
    default:
      UNREACHABLE();
  }
}

void BytecodeGenerator::VisitDelete(UnaryOperation* unary) {
  Expression* expr = unary->expression();
  if (expr->IsProperty()) {
    // Delete of an object property is allowed both in sloppy
    // and strict modes.
    Property* property = expr->AsProperty();
    DCHECK(!property->IsPrivateReference());
    if (property->IsSuperAccess()) {
      // Delete of super access is not allowed.
      VisitForEffect(property->key());
      builder()->CallRuntime(Runtime::kThrowUnsupportedSuperError);
    } else {
      Register object = VisitForRegisterValue(property->obj());
      VisitForAccumulatorValue(property->key());
      builder()->Delete(object, language_mode());
    }
  } else if (expr->IsOptionalChain()) {
    Expression* expr_inner = expr->AsOptionalChain()->expression();
    if (expr_inner->IsProperty()) {
      Property* property = expr_inner->AsProperty();
      DCHECK(!property->IsPrivateReference());
      BytecodeLabel done;
      OptionalChainNullLabelScope label_scope(this);
      VisitForAccumulatorValue(property->obj());
      if (property->is_optional_chain_link()) {
        int right_range = AllocateBlockCoverageSlotIfEnabled(
            property, SourceRangeKind::kRight);
        builder()->JumpIfUndefinedOrNull(label_scope.labels()->New());
        BuildIncrementBlockCoverageCounterIfEnabled(right_range);
      }
      Register object = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(object);
      if (property->is_optional_chain_link()) {
        VisitInHoleCheckElisionScopeForAccumulatorValue(property->key());
      } else {
        VisitForAccumulatorValue(property->key());
      }
      builder()->Delete(object, language_mode());
      builder()->Jump(&done);
      label_scope.labels()->Bind(builder());
      builder()->LoadTrue();
      builder()->Bind(&done);
    } else {
      VisitForEffect(expr);
      builder()->LoadTrue();
    }
  } else if (expr->IsVariableProxy() &&
             !expr->AsVariableProxy()->is_new_target()) {
    // Delete of an unqualified identifier is allowed in sloppy mode but is
    // not allowed in strict mode.
    DCHECK(is_sloppy(language_mode()));
    Variable* variable = expr->AsVariableProxy()->var();
    switch (variable->location()) {
      case VariableLocation::PARAMETER:
      case VariableLocation::LOCAL:
      case VariableLocation::CONTEXT:
      case VariableLocation::REPL_GLOBAL: {
        // Deleting local var/let/const, context variables, and arguments
        // does not have any effect.
        builder()->LoadFalse();
        break;
      }
      case VariableLocation::UNALLOCATED:
      // TODO(adamk): Falling through to the runtime results in correct
      // behavior, but does unnecessary context-walking (since scope
      // analysis has already proven that the variable doesn't exist in
      // any non-global scope). Consider adding a DeleteGlobal bytecode
      // that knows how to deal with ScriptContexts as well as global
      // object properties.
      case VariableLocation::LOOKUP: {
        Register name_reg = register_allocator()->NewRegister();
        builder()
            ->LoadLiteral(variable->raw_name())
            .StoreAccumulatorInRegister(name_reg)
            .CallRuntime(Runtime::kDeleteLookupSlot, name_reg);
        break;
      }
      case VariableLocation::MODULE:
        // Modules are always in strict mode and unqualified identifers are not
        // allowed in strict mode.
        UNREACHABLE();
    }
  } else {
    // Delete of an unresolvable reference, new.target, and this returns true.
    VisitForEffect(expr);
    builder()->LoadTrue();
  }
}

void BytecodeGenerator::VisitCountOperation(CountOperation* expr) {
  DCHECK(expr->expression()->IsValidReferenceExpression());

  // Left-hand side can only be a property, a global or a variable slot.
  Property* property = expr->expression()->AsProperty();
  AssignType assign_type = Property::GetAssignType(property);

  bool is_postfix = expr->is_postfix() && !execution_result()->IsEffect();

  // Evaluate LHS expression and get old value.
  Register object, key, old_value;
  RegisterList super_property_args;
  const AstRawString* name;
  switch (assign_type) {
    case NON_PROPERTY: {
      VariableProxy* proxy = expr->expression()->AsVariableProxy();
      BuildVariableLoadForAccumulatorValue(proxy->var(),
                                           proxy->hole_check_mode());
      break;
    }
    case NAMED_PROPERTY: {
      object = VisitForRegisterValue(property->obj());
      name = property->key()->AsLiteral()->AsRawPropertyName();
      builder()->LoadNamedProperty(
          object, name,
          feedback_index(GetCachedLoadICSlot(property->obj(), name)));
      break;
    }
    case KEYED_PROPERTY: {
      object = VisitForRegisterValue(property->obj());
      // Use visit for accumulator here since we need the key in the accumulator
      // for the LoadKeyedProperty.
      key = register_allocator()->NewRegister();
      VisitForAccumulatorValue(property->key());
      builder()->StoreAccumulatorInRegister(key).LoadKeyedProperty(
          object, feedback_index(feedback_spec()->AddKeyedLoadICSlot()));
      break;
    }
    case NAMED_SUPER_PROPERTY: {
      super_property_args = register_allocator()->NewRegisterList(4);
      RegisterList load_super_args = super_property_args.Truncate(3);
      BuildThisVariableLoad();
      builder()->StoreAccumulatorInRegister(load_super_args[0]);
      BuildVariableLoad(
          property->obj()->AsSuperPropertyReference()->home_object()->var(),
          HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(load_super_args[1]);
      builder()
          ->LoadLiteral(property->key()->AsLiteral()->AsRawPropertyName())
          .StoreAccumulatorInRegister(load_super_args[2])
          .CallRuntime(Runtime::kLoadFromSuper, load_super_args);
      break;
    }
    case KEYED_SUPER_PROPERTY: {
      super_property_args = register_allocator()->NewRegisterList(4);
      RegisterList load_super_args = super_property_args.Truncate(3);
      BuildThisVariableLoad();
      builder()->StoreAccumulatorInRegister(load_super_args[0]);
      BuildVariableLoad(
          property->obj()->AsSuperPropertyReference()->home_object()->var(),
          HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(load_super_args[1]);
      VisitForRegisterValue(property->key(), load_super_args[2]);
      builder()->CallRuntime(Runtime::kLoadKeyedFromSuper, load_super_args);
      break;
    }
    case PRIVATE_METHOD: {
      object = VisitForRegisterValue(property->obj());
      BuildPrivateBrandCheck(property, object);
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateMethodWrite,
                                 property);
      return;
    }
    case PRIVATE_GETTER_ONLY: {
      object = VisitForRegisterValue(property->obj());
      BuildPrivateBrandCheck(property, object);
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateSetterAccess,
                                 property);
      return;
    }
    case PRIVATE_SETTER_ONLY: {
      object = VisitForRegisterValue(property->obj());
      BuildPrivateBrandCheck(property, object);
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateGetterAccess,
                                 property);
      return;
    }
    case PRIVATE_GETTER_AND_SETTER: {
      object = VisitForRegisterValue(property->obj());
      key = VisitForRegisterValue(property->key());
      BuildPrivateBrandCheck(property, object);
      BuildPrivateGetterAccess(object, key);
      break;
    }
    case PRIVATE_DEBUG_DYNAMIC: {
      object = VisitForRegisterValue(property->obj());
      BuildPrivateDebugDynamicGet(property, object);
      break;
    }
  }

  // Save result for postfix expressions.
  FeedbackSlot count_slot = feedback_spec()->AddBinaryOpICSlot();
  if (is_postfix) {
    old_value = register_allocator()->NewRegister();
    // Convert old value into a number before saving it.
    // TODO(ignition): Think about adding proper PostInc/PostDec bytecodes
    // instead of this ToNumeric + Inc/Dec dance.
    builder()
        ->ToNumeric(feedback_index(count_slot))
        .StoreAccumulatorInRegister(old_value);
  }

  // Perform +1/-1 operation.
  builder()->UnaryOperation(expr->op(), feedback_index(count_slot));

  // Store the value.
  builder()->SetExpressionPosition(expr);
  switch (assign_type) {
    case NON_PROPERTY: {
      VariableProxy* proxy = expr->expression()->AsVariableProxy();
      BuildVariableAssignment(proxy->var(), expr->op(),
                              proxy->hole_check_mode());
      break;
    }
    case NAMED_PROPERTY: {
      FeedbackSlot slot = GetCachedStoreICSlot(property->obj(), name);
      Register value;
      if (!execution_result()->IsEffect()) {
        value = register_allocator()->NewRegister();
        builder()->StoreAccumulatorInRegister(value);
      }
      builder()->SetNamedProperty(object, name, feedback_index(slot),
                                  language_mode());
      if (!execution_result()->IsEffect()) {
        builder()->LoadAccumulatorWithRegister(value);
      }
      break;
    }
    case KEYED_PROPERTY: {
      FeedbackSlot slot = feedback_spec()->AddKeyedStoreICSlot(language_mode());
      Register value;
      if (!execution_result()->IsEffect()) {
        value = register_allocator()->NewRegister();
        builder()->StoreAccumulatorInRegister(value);
      }
      builder()->SetKeyedProperty(object, key, feedback_index(slot),
                                  language_mode());
      if (!execution_result()->IsEffect()) {
        builder()->LoadAccumulatorWithRegister(value);
      }
      break;
    }
    case NAMED_SUPER_PROPERTY: {
      builder()
          ->StoreAccumulatorInRegister(super_property_args[3])
          .CallRuntime(Runtime::kStoreToSuper, super_property_args);
      break;
    }
    case KEYED_SUPER_PROPERTY: {
      builder()
          ->StoreAccumulatorInRegister(super_property_args[3])
          .CallRuntime(Runtime::kStoreKeyedToSuper, super_property_args);
      break;
    }
    case PRIVATE_SETTER_ONLY:
    case PRIVATE_GETTER_ONLY:
    case PRIVATE_METHOD: {
      UNREACHABLE();
    }
    case PRIVATE_GETTER_AND_SETTER: {
      Register value = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(value);
      BuildPrivateSetterAccess(object, key, value);
      if (!execution_result()->IsEffect()) {
        builder()->LoadAccumulatorWithRegister(value);
      }
      break;
    }
    case PRIVATE_DEBUG_DYNAMIC: {
      Register value = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(value);
      BuildPrivateDebugDynamicSet(property, object, value);
      break;
    }
  }

  // Restore old value for postfix expressions.
  if (is_postfix) {
    builder()->LoadAccumulatorWithRegister(old_value);
  }
}

void BytecodeGenerator::VisitBinaryOperation(BinaryOperation* binop) {
  switch (binop->op()) {
    case Token::kComma:
      VisitCommaExpression(binop);
      break;
    case Token::kOr:
      VisitLogicalOrExpression(binop);
      break;
    case Token::kAnd:
      VisitLogicalAndExpression(binop);
      break;
    case Token::kNullish:
      VisitNullishExpression(binop);
      break;
    default:
      VisitArithmeticExpression(binop);
      break;
  }
}

void BytecodeGenerator::VisitNaryOperation(NaryOperation* expr) {
  switch (expr->op()) {
    case Token::kComma:
      VisitNaryCommaExpression(expr);
      break;
    case Token::kOr:
      VisitNaryLogicalOrExpression(expr);
      break;
    case Token::kAnd:
      VisitNaryLogicalAndExpression(expr);
      break;
    case Token::kNullish:
      VisitNaryNullishExpression(expr);
      break;
    default:
      VisitNaryArithmeticExpression(expr);
      break;
  }
}

void BytecodeGenerator::BuildLiteralCompareNil(
    Token::Value op, BytecodeArrayBuilder::NilValue nil) {
  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    switch (test_result->fallthrough()) {
      case TestFallthrough::kThen:
        builder()->JumpIfNotNil(test_result->NewElseLabel(), op, nil);
        break;
      case TestFallthrough::kElse:
        builder()->JumpIfNil(test_result->NewThenLabel(), op, nil);
        break;
      case TestFallthrough::kNone:
        builder()
            ->JumpIfNil(test_result->NewThenLabel(), op, nil)
            .Jump(test_result->NewElseLabel());
    }
    test_result->SetResultConsumedByTest();
  } else {
    builder()->CompareNil(op, nil);
  }
}

void BytecodeGenerator::BuildLiteralStrictCompareBoolean(Literal* literal) {
  DCHECK(literal->IsBooleanLiteral());
  Register result = register_allocator()->NewRegister();
  builder()->StoreAccumulatorInRegister(result);
  builder()->LoadBoolean(literal->AsBooleanLiteral());
  builder()->CompareReference(result);
}

bool BytecodeGenerator::IsLocalVariableWithInternalizedStringHint(
    Expression* expr) {
  VariableProxy* proxy = expr->AsVariableProxy();
  return proxy != nullptr && proxy->is_resolved() &&
         proxy->var()->IsStackLocal() &&
         GetTypeHintForLocalVariable(proxy->var()) ==
             TypeHint::kInternalizedString;
}

static bool IsTypeof(Expression* expr) {
  UnaryOperation* maybe_unary = expr->AsUnaryOperation();
  return maybe_unary != nullptr && maybe_unary->op() == Token::kTypeOf;
}

static bool IsCharU(const AstRawString* str) {
  return str->length() == 1 && str->FirstCharacter() == 'u';
}

static bool IsLiteralCompareTypeof(CompareOperation* expr,
                                   Expression** sub_expr,
                                   TestTypeOfFlags::LiteralFlag* flag,
                                   const AstStringConstants* ast_constants) {
  if (IsTypeof(expr->left()) && expr->right()->IsStringLiteral()) {
    Literal* right_lit = expr->right()->AsLiteral();

    if (Token::IsEqualityOp(expr->op())) {
      // typeof(x) === 'string'
      *flag = TestTypeOfFlags::GetFlagForLiteral(ast_constants, right_lit);
    } else if (expr->op() == Token::kGreaterThan &&
               IsCharU(right_lit->AsRawString())) {
      // typeof(x) > 'u'
      // Minifier may convert `typeof(x) === 'undefined'` to this form,
      // since `undefined` is the only valid value that is greater than 'u'.
      // Check the test OnlyUndefinedGreaterThanU in bytecodes-unittest.cc
      *flag = TestTypeOfFlags::LiteralFlag::kUndefined;
    } else {
      return false;
    }

    *sub_expr = expr->left()->AsUnaryOperation()->expression();
    return true;
  }

  if (IsTypeof(expr->right()) && expr->left()->IsStringLiteral()) {
    Literal* left_lit = expr->left()->AsLiteral();

    if (Token::IsEqualityOp(expr->op())) {
      // 'string' === typeof(x)
      *flag = TestTypeOfFlags::GetFlagForLiteral(ast_constants, left_lit);
    } else if (expr->op() == Token::kLessThan &&
               IsCharU(left_lit->AsRawString())) {
      // 'u' < typeof(x)
      *flag = TestTypeOfFlags::LiteralFlag::kUndefined;
    } else {
      return false;
    }

    *sub_expr = expr->right()->AsUnaryOperation()->expression();
    return true;
  }

  return false;
}

void BytecodeGenerator::VisitCompareOperation(CompareOperation* expr) {
  Expression* sub_expr;
  Literal* literal;
  TestTypeOfFlags::LiteralFlag flag;
  if (IsLiteralCompareTypeof(expr, &sub_expr, &flag, ast_string_constants())) {
    // Emit a fast literal comparion for expressions of the form:
    // typeof(x) === 'string'.
    VisitForTypeOfValue(sub_expr);
    builder()->SetExpressionPosition(expr);
    if (flag == TestTypeOfFlags::LiteralFlag::kOther) {
      builder()->LoadFalse();
    } else {
      builder()->CompareTypeOf(flag);
    }
  } else if (expr->IsLiteralStrictCompareBoolean(&sub_expr, &literal)) {
    DCHECK(expr->op() == Token::kEqStrict);
    VisitForAccumulatorValue(sub_expr);
    builder()->SetExpressionPosition(expr);
    BuildLiteralStrictCompareBoolean(literal);
  } else if (expr->IsLiteralCompareUndefined(&sub_expr)) {
    VisitForAccumulatorValue(sub_expr);
    builder()->SetExpressionPosition(expr);
    BuildLiteralCompareNil(expr->op(), BytecodeArrayBuilder::kUndefinedValue);
  } else if (expr->IsLiteralCompareNull(&sub_expr)) {
    VisitForAccumulatorValue(sub_expr);
    builder()->SetExpressionPosition(expr);
    BuildLiteralCompareNil(expr->op(), BytecodeArrayBuilder::kNullValue);
  } else if (expr->IsLiteralCompareEqualVariable(&sub_expr, &literal) &&
             IsLocalVariableWithInternalizedStringHint(sub_expr)) {
    builder()->LoadLiteral(literal->AsRawString());
    builder()->CompareReference(
        GetRegisterForLocalVariable(sub_expr->AsVariableProxy()->var()));
  } else {
    if (expr->op() == Token::kIn && expr->left()->IsPrivateName()) {
      Variable* var = expr->left()->AsVariableProxy()->var();
      if (IsPrivateMethodOrAccessorVariableMode(var->mode())) {
        BuildPrivateMethodIn(var, expr->right());
        return;
      }
      // For private fields, the code below does the right thing.
    }

    Register lhs = VisitForRegisterValue(expr->left());
    VisitForAccumulatorValue(expr->right());
    builder()->SetExpressionPosition(expr);
    FeedbackSlot slot;
    if (expr->op() == Token::kIn) {
      slot = feedback_spec()->AddKeyedHasICSlot();
    } else if (expr->op() == Token::kInstanceOf) {
      slot = feedback_spec()->AddInstanceOfSlot();
    } else {
      slot = feedback_spec()->AddCompareICSlot();
    }
    builder()->CompareOperation(expr->op(), lhs, feedback_index(slot));
  }
  // Always returns a boolean value.
  execution_result()->SetResultIsBoolean();
}

void BytecodeGenerator::VisitArithmeticExpression(BinaryOperation* expr) {
  FeedbackSlot slot = feedback_spec()->AddBinaryOpICSlot();
  Expression* subexpr;
  Tagged<Smi> literal;
  if (expr->IsSmiLiteralOperation(&subexpr, &literal)) {
    TypeHint type_hint = VisitForAccumulatorValue(subexpr);
    builder()->SetExpressionPosition(expr);
    builder()->BinaryOperationSmiLiteral(expr->op(), literal,
                                         feedback_index(slot));
    if (expr->op() == Token::kAdd && IsStringTypeHint(type_hint)) {
      execution_result()->SetResultIsString();
    }
  } else {
    TypeHint lhs_type = VisitForAccumulatorValue(expr->left());
    Register lhs = register_allocator()->NewRegister();
    builder()->StoreAccumulatorInRegister(lhs);
    TypeHint rhs_type = VisitForAccumulatorValue(expr->right());
    if (expr->op() == Token::kAdd &&
        (IsStringTypeHint(lhs_type) || IsStringTypeHint(rhs_type))) {
      execution_result()->SetResultIsString();
    }

    builder()->SetExpressionPosition(expr);
    builder()->BinaryOperation(expr->op(), lhs, feedback_index(slot));
  }
}

void BytecodeGenerator::VisitNaryArithmeticExpression(NaryOperation* expr) {
  // TODO(leszeks): Add support for lhs smi in commutative ops.
  TypeHint type_hint = VisitForAccumulatorValue(expr->first());

  for (size_t i = 0; i < expr->subsequent_length(); ++i) {
    RegisterAllocationScope register_scope(this);
    if (expr->subsequent(i)->IsSmiLiteral()) {
      builder()->SetExpressionPosition(expr->subsequent_op_position(i));
      builder()->BinaryOperationSmiLiteral(
          expr->op(), expr->subsequent(i)->AsLiteral()->AsSmiLiteral(),
          feedback_index(feedback_spec()->AddBinaryOpICSlot()));
    } else {
      Register lhs = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(lhs);
      TypeHint rhs_hint = VisitForAccumulatorValue(expr->subsequent(i));
      if (IsStringTypeHint(rhs_hint)) type_hint = TypeHint::kString;
      builder()->SetExpressionPosition(expr->subsequent_op_position(i));
      builder()->BinaryOperation(
          expr->op(), lhs,
          feedback_index(feedback_spec()->AddBinaryOpICSlot()));
    }
  }

  if (IsStringTypeHint(type_hint) && expr->op() == Token::kAdd) {
    // If any operand of an ADD is a String, a String is produced.
    execution_result()->SetResultIsString();
  }
}

// Note: the actual spreading is performed by the surrounding expression's
// visitor.
void BytecodeGenerator::VisitSpread(Spread* expr) { Visit(expr->expression()); }

void BytecodeGenerator::VisitEmptyParentheses(EmptyParentheses* expr) {
  UNREACHABLE();
}

void BytecodeGenerator::VisitImportCallExpression(ImportCallExpression* expr) {
  const int register_count = expr->import_options() ? 4 : 3;
  // args is a list of [ function_closure, specifier, phase, import_options ].
  RegisterList args = register_allocator()->NewRegisterList(register_count);

  builder()->MoveRegister(Register::function_closure(), args[0]);
  VisitForRegisterValue(expr->specifier(), args[1]);
  builder()
      ->LoadLiteral(Smi::FromInt(static_cast<int>(expr->phase())))
      .StoreAccumulatorInRegister(args[2]);

  if (expr->import_options()) {
    VisitForRegisterValue(expr->import_options(), args[3]);
  }

  builder()->CallRuntime(Runtime::kDynamicImportCall, args);
}

void BytecodeGenerator::BuildGetIterator(IteratorType hint) {
  if (hint == IteratorType::kAsync) {
    RegisterAllocationScope scope(this);

    Register obj = register_allocator()->NewRegister();
    Register method = register_allocator()->NewRegister();

    // Set method to GetMethod(obj, @@asyncIterator)
    builder()->StoreAccumulatorInRegister(obj).LoadAsyncIteratorProperty(
        obj, feedback_index(feedback_spec()->AddLoadICSlot()));

    BytecodeLabel async_iterator_undefined, done;
    builder()->JumpIfUndefinedOrNull(&async_iterator_undefined);

    // Let iterator be Call(method, obj)
    builder()->StoreAccumulatorInRegister(method).CallProperty(
        method, RegisterList(obj),
        feedback_index(feedback_spec()->AddCallICSlot()));

    // If Type(iterator) is not Object, throw a TypeError exception.
    builder()->JumpIfJSReceiver(&done);
    builder()->CallRuntime(Runtime::kThrowSymbolAsyncIteratorInvalid);

    builder()->Bind(&async_iterator_undefined);
    // If method is undefined,
    //     Let syncMethod be GetMethod(obj, @@iterator)
    builder()
        ->LoadIteratorProperty(obj,
                               feedback_index(feedback_spec()->AddLoadICSlot()))
        .StoreAccumulatorInRegister(method);

    //     Let syncIterator be Call(syncMethod, obj)
    builder()->CallProperty(method, RegisterList(obj),
                            feedback_index(feedback_spec()->AddCallICSlot()));

    // Return CreateAsyncFromSyncIterator(syncIterator)
    // alias `method` register as it's no longer used
    Register sync_iter = method;
    builder()->StoreAccumulatorInRegister(sync_iter).CallRuntime(
        Runtime::kInlineCreateAsyncFromSyncIterator, sync_iter);

    builder()->Bind(&done);
  } else {
    {
      RegisterAllocationScope scope(this);

      Register obj = register_allocator()->NewRegister();
      int load_feedback_index =
          feedback_index(feedback_spec()->AddLoadICSlot());
      int call_feedback_index =
          feedback_index(feedback_spec()->AddCallICSlot());

      // Let method be GetMethod(obj, @@iterator) and
      // iterator be Call(method, obj). If iterator is
      // not JSReceiver, then throw TypeError.
      builder()->StoreAccumulatorInRegister(obj).GetIterator(
          obj, load_feedback_index, call_feedback_index);
    }
  }
}

// Returns an IteratorRecord which is valid for the lifetime of the current
// register_allocation_scope.
BytecodeGenerator::IteratorRecord BytecodeGenerator::BuildGetIteratorRecord(
    Register next, Register object, IteratorType hint) {
  DCHECK(next.is_valid() && object.is_valid());
  BuildGetIterator(hint);

  builder()
      ->StoreAccumulatorInRegister(object)
      .LoadNamedProperty(object, ast_string_constants()->next_string(),
                         feedback_index(feedback_spec()->AddLoadICSlot()))
      .StoreAccumulatorInRegister(next);
  return IteratorRecord(object, next, hint);
}

BytecodeGenerator::IteratorRecord BytecodeGenerator::BuildGetIteratorRecord(
    IteratorType hint) {
  Register next = register_allocator()->NewRegister();
  Register object = register_allocator()->NewRegister();
  return BuildGetIteratorRecord(next, object, hint);
}

void BytecodeGenerator::BuildIteratorNext(const IteratorRecord& iterator,
                                          Register next_result) {
  DCHECK(next_result.is_valid());
  builder()->CallProperty(iterator.next(), RegisterList(iterator.object()),
                          feedback_index(feedback_spec()->AddCallICSlot()));

  if (iterator.type() == IteratorType::kAsync) {
    BuildAwait();
  }

  BytecodeLabel is_object;
  builder()
      ->StoreAccumulatorInRegister(next_result)
      .JumpIfJSReceiver(&is_object)
      .CallRuntime(Runtime::kThrowIteratorResultNotAnObject, next_result)
      .Bind(&is_object);
}

void BytecodeGenerator::BuildCallIteratorMethod(Register iterator,
                                                const AstRawString* method_name,
                                                RegisterList receiver_and_args,
                                                BytecodeLabel* if_called,
                                                BytecodeLabels* if_notcalled) {
  RegisterAllocationScope register_scope(this);

  Register method = register_allocator()->NewRegister();
  FeedbackSlot slot = feedback_spec()->AddLoadICSlot();
  builder()
      ->LoadNamedProperty(iterator, method_name, feedback_index(slot))
      .JumpIfUndefinedOrNull(if_notcalled->New())
      .StoreAccumulatorInRegister(method)
      .CallProperty(method, receiver_and_args,
                    feedback_index(feedback_spec()->AddCallICSlot()))
      .Jump(if_called);
}

void BytecodeGenerator::BuildIteratorClose(const IteratorRecord& iterator,
                                           Expression* expr) {
  RegisterAllocationScope register_scope(this);
  BytecodeLabels done(zone());
  BytecodeLabel if_called;
  RegisterList args = RegisterList(iterator.object());
  BuildCallIteratorMethod(iterator.object(),
                          ast_string_constants()->return_string(), args,
                          &if_called, &done);
  builder()->Bind(&if_called);

  if (iterator.type() == IteratorType::kAsync) {
    DCHECK_NOT_NULL(expr);
    BuildAwait(expr->position());
  }

  builder()->JumpIfJSReceiver(done.New());
  {
    RegisterAllocationScope inner_register_scope(this);
    Register return_result = register_allocator()->NewRegister();
    builder()
        ->StoreAccumulatorInRegister(return_result)
        .CallRuntime(Runtime::kThrowIteratorResultNotAnObject, return_result);
  }

  done.Bind(builder());
}

void BytecodeGenerator::VisitGetTemplateObject(GetTemplateObject* expr) {
  builder()->SetExpressionPosition(expr);
  size_t entry = builder()->AllocateDeferredConstantPoolEntry();
  template_objects_.push_back(std::make_pair(expr, entry));
  FeedbackSlot literal_slot = feedback_spec()->AddLiteralSlot();
  builder()->GetTemplateObject(entry, feedback_index(literal_slot));
}

void BytecodeGenerator::VisitTemplateLiteral(TemplateLiteral* expr) {
  const ZonePtrList<const AstRawString>& parts = *expr->string_parts();
  const ZonePtrList<Expression>& substitutions = *expr->substitutions();
  // Template strings with no substitutions are turned into StringLiterals.
  DCHECK_GT(substitutions.length(), 0);
  DCHECK_EQ(parts.length(), substitutions.length() + 1);

  // Generate string concatenation
  // TODO(caitp): Don't generate feedback slot if it's not used --- introduce
  // a simple, concise, reusable mechanism to lazily create reusable slots.
  FeedbackSlot slot = feedback_spec()->AddBinaryOpICSlot();
  Register last_part = register_allocator()->NewRegister();
  bool last_part_valid = false;

  builder()->SetExpressionPosition(expr);
  for (int i = 0; i < substitutions.length(); ++i) {
    if (i != 0) {
      builder()->StoreAccumulatorInRegister(last_part);
      last_part_valid = true;
    }

    if (!parts[i]->IsEmpty()) {
      builder()->LoadLiteral(parts[i]);
      if (last_part_valid) {
        builder()->BinaryOperation(Token::kAdd, last_part,
                                   feedback_index(slot));
      }
      builder()->StoreAccumulatorInRegister(last_part);
      last_part_valid = true;
    }

    TypeHint type_hint = VisitForAccumulatorValue(substitutions[i]);
    if (!IsStringTypeHint(type_hint)) {
      builder()->ToString();
    }
    if (last_part_valid) {
      builder()->BinaryOperation(Token::kAdd, last_part, feedback_index(slot));
    }
    last_part_valid = false;
  }

  if (!parts.last()->IsEmpty()) {
    builder()->StoreAccumulatorInRegister(last_part);
    builder()->LoadLiteral(parts.last());
    builder()->BinaryOperation(Token::kAdd, last_part, feedback_index(slot));
  }
}

void BytecodeGenerator::BuildThisVariableLoad() {
  DeclarationScope* receiver_scope = closure_scope()->GetReceiverScope();
  Variable* var = receiver_scope->receiver();
  // TODO(littledan): implement 'this' hole check elimination.
  HoleCheckMode hole_check_mode =
      IsDerivedConstructor(receiver_scope->function_kind())
          ? HoleCheckMode::kRequired
          : HoleCheckMode::kElided;
  BuildVariableLoad(var, hole_check_mode);
}

void BytecodeGenerator::VisitThisExpression(ThisExpression* expr) {
  BuildThisVariableLoad();
}

void BytecodeGenerator::VisitSuperCallReference(SuperCallReference* expr) {
  // Handled by VisitCall().
  UNREACHABLE();
}

void BytecodeGenerator::VisitSuperPropertyReference(
    SuperPropertyReference* expr) {
  // Handled by VisitAssignment(), VisitCall(), VisitDelete() and
  // VisitPropertyLoad().
  UNREACHABLE();
}

void BytecodeGenerator::VisitCommaExpression(BinaryOperation* binop) {
  VisitForEffect(binop->left());
  builder()->SetExpressionAsStatementPosition(binop->right());
  Visit(binop->right());
}

void BytecodeGenerator::VisitNaryCommaExpression(NaryOperation* expr) {
  DCHECK_GT(expr->subsequent_length(), 0);

  VisitForEffect(expr->first());
  for (size_t i = 0; i < expr->subsequent_length() - 1; ++i) {
    builder()->SetExpressionAsStatementPosition(expr->subsequent(i));
    VisitForEffect(expr->subsequent(i));
  }
  builder()->SetExpressionAsStatementPosition(
      expr->subsequent(expr->subsequent_length() - 1));
  Visit(expr->subsequent(expr->subsequent_length() - 1));
}

void BytecodeGenerator::VisitLogicalTestSubExpression(
    Token::Value token, Expression* expr, BytecodeLabels* then_labels,
    BytecodeLabels* else_labels, int coverage_slot) {
  DCHECK(token == Token::kOr || token == Token::kAnd ||
         token == Token::kNullish);

  BytecodeLabels test_next(zone());
  if (token == Token::kOr) {
    VisitForTest(expr, then_labels, &test_next, TestFallthrough::kElse);
  } else if (token == Token::kAnd) {
    VisitForTest(expr, &test_next, else_labels, TestFallthrough::kThen);
  } else {
    DCHECK_EQ(Token::kNullish, token);
    VisitForNullishTest(expr, then_labels, &test_next, else_labels);
  }
  test_next.Bind(builder());

  BuildIncrementBlockCoverageCounterIfEnabled(coverage_slot);
}

void BytecodeGenerator::VisitLogicalTest(Token::Value token, Expression* left,
                                         Expression* right,
                                         int right_coverage_slot) {
  DCHECK(token == Token::kOr || token == Token::kAnd ||
         token == Token::kNullish);
  TestResultScope* test_result = execution_result()->AsTest();
  BytecodeLabels* then_labels = test_result->then_labels();
  BytecodeLabels* else_labels = test_result->else_labels();
  TestFallthrough fallthrough = test_result->fallthrough();

  VisitLogicalTestSubExpression(token, left, then_labels, else_labels,
                                right_coverage_slot);
  // The last test has the same then, else and fallthrough as the parent test.
  HoleCheckElisionScope elider(this);
  VisitForTest(right, then_labels, else_labels, fallthrough);
}

void BytecodeGenerator::VisitNaryLogicalTest(
    Token::Value token, NaryOperation* expr,
    const NaryCodeCoverageSlots* coverage_slots) {
  DCHECK(token == Token::kOr || token == Token::kAnd ||
         token == Token::kNullish);
  DCHECK_GT(expr->subsequent_length(), 0);

  TestResultScope* test_result = execution_result()->AsTest();
  BytecodeLabels* then_labels = test_result->then_labels();
  BytecodeLabels* else_labels = test_result->else_labels();
  TestFallthrough fallthrough = test_result->fallthrough();

  VisitLogicalTestSubExpression(token, expr->first(), then_labels, else_labels,
                                coverage_slots->GetSlotFor(0));
  HoleCheckElisionScope elider(this);
  for (size_t i = 0; i < expr->subsequent_length() - 1; ++i) {
    VisitLogicalTestSubExpression(token, expr->subsequent(i), then_labels,
                                  else_labels,
                                  coverage_slots->GetSlotFor(i + 1));
  }
  // The last test has the same then, else and fallthrough as the parent test.
  VisitForTest(expr->subsequent(expr->subsequent_length() - 1), then_labels,
               else_labels, fallthrough);
}

bool BytecodeGenerator::VisitLogicalOrSubExpression(Expression* expr,
                                                    BytecodeLabels* end_labels,
                                                    int coverage_slot) {
  if (expr->ToBooleanIsTrue()) {
    VisitForAccumulatorValue(expr);
    end_labels->Bind(builder());
    return true;
  } else if (!expr->ToBooleanIsFalse()) {
    TypeHint type_hint = VisitForAccumulatorValue(expr);
    builder()->JumpIfTrue(ToBooleanModeFromTypeHint(type_hint),
                          end_labels->New());
  }

  BuildIncrementBlockCoverageCounterIfEnabled(coverage_slot);

  return false;
}

bool BytecodeGenerator::VisitLogicalAndSubExpression(Expression* expr,
                                                     BytecodeLabels* end_labels,
                                                     int coverage_slot) {
  if (expr->ToBooleanIsFalse()) {
    VisitForAccumulatorValue(expr);
    end_labels->Bind(builder());
    return true;
  } else if (!expr->ToBooleanIsTrue()) {
    TypeHint type_hint = VisitForAccumulatorValue(expr);
    builder()->JumpIfFalse(ToBooleanModeFromTypeHint(type_hint),
                           end_labels->New());
  }

  BuildIncrementBlockCoverageCounterIfEnabled(coverage_slot);

  return false;
}

bool BytecodeGenerator::VisitNullishSubExpression(Expression* expr,
                                                  BytecodeLabels* end_labels,
                                                  int coverage_slot) {
  if (expr->IsLiteralButNotNullOrUndefined()) {
    VisitForAccumulatorValue(expr);
    end_labels->Bind(builder());
    return true;
  } else if (!expr->IsNullOrUndefinedLiteral()) {
    VisitForAccumulatorValue(expr);
    BytecodeLabel is_null_or_undefined;
    builder()
        ->JumpIfUndefinedOrNull(&is_null_or_undefined)
        .Jump(end_labels->New());
    builder()->Bind(&is_null_or_undefined);
  }

  BuildIncrementBlockCoverageCounterIfEnabled(coverage_slot);

  return false;
}

void BytecodeGenerator::VisitLogicalOrExpression(BinaryOperation* binop) {
  Expression* left = binop->left();
  Expression* right = binop->right();

  int right_coverage_slot =
      AllocateBlockCoverageSlotIfEnabled(binop, SourceRangeKind::kRight);

  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    if (left->ToBooleanIsTrue()) {
      builder()->Jump(test_result->NewThenLabel());
    } else if (left->ToBooleanIsFalse() && right->ToBooleanIsFalse()) {
      BuildIncrementBlockCoverageCounterIfEnabled(right_coverage_slot);
      builder()->Jump(test_result->NewElseLabel());
    } else {
      VisitLogicalTest(Token::kOr, left, right, right_coverage_slot);
    }
    test_result->SetResultConsumedByTest();
  } else {
    BytecodeLabels end_labels(zone());
    if (VisitLogicalOrSubExpression(left, &end_labels, right_coverage_slot)) {
      return;
    }
    VisitInHoleCheckElisionScopeForAccumulatorValue(right);
    end_labels.Bind(builder());
  }
}

void BytecodeGenerator::VisitNaryLogicalOrExpression(NaryOperation* expr) {
  Expression* first = expr->first();
  DCHECK_GT(expr->subsequent_length(), 0);

  NaryCodeCoverageSlots coverage_slots(this, expr);

  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    if (first->ToBooleanIsTrue()) {
      builder()->Jump(test_result->NewThenLabel());
    } else {
      VisitNaryLogicalTest(Token::kOr, expr, &coverage_slots);
    }
    test_result->SetResultConsumedByTest();
  } else {
    BytecodeLabels end_labels(zone());
    if (VisitLogicalOrSubExpression(first, &end_labels,
                                    coverage_slots.GetSlotFor(0))) {
      return;
    }

    HoleCheckElisionScope elider(this);
    for (size_t i = 0; i < expr->subsequent_length() - 1; ++i) {
      if (VisitLogicalOrSubExpression(expr->subsequent(i), &end_labels,
                                      coverage_slots.GetSlotFor(i + 1))) {
        return;
      }
    }
    // We have to visit the last value even if it's true, because we need its
    // actual value.
    VisitForAccumulatorValue(expr->subsequent(expr->subsequent_length() - 1));
    end_labels.Bind(builder());
  }
}

void BytecodeGenerator::VisitLogicalAndExpression(BinaryOperation* binop) {
  Expression* left = binop->left();
  Expression* right = binop->right();

  int right_coverage_slot =
      AllocateBlockCoverageSlotIfEnabled(binop, SourceRangeKind::kRight);

  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    if (left->ToBooleanIsFalse()) {
      builder()->Jump(test_result->NewElseLabel());
    } else if (left->ToBooleanIsTrue() && right->ToBooleanIsTrue()) {
      BuildIncrementBlockCoverageCounterIfEnabled(right_coverage_slot);
      builder()->Jump(test_result->NewThenLabel());
    } else {
      VisitLogicalTest(Token::kAnd, left, right, right_coverage_slot);
    }
    test_result->SetResultConsumedByTest();
  } else {
    BytecodeLabels end_labels(zone());
    if (VisitLogicalAndSubExpression(left, &end_labels, right_coverage_slot)) {
      return;
    }
    VisitInHoleCheckElisionScopeForAccumulatorValue(right);
    end_labels.Bind(builder());
  }
}

void BytecodeGenerator::VisitNaryLogicalAndExpression(NaryOperation* expr) {
  Expression* first = expr->first();
  DCHECK_GT(expr->subsequent_length(), 0);

  NaryCodeCoverageSlots coverage_slots(this, expr);

  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    if (first->ToBooleanIsFalse()) {
      builder()->Jump(test_result->NewElseLabel());
    } else {
      VisitNaryLogicalTest(Token::kAnd, expr, &coverage_slots);
    }
    test_result->SetResultConsumedByTest();
  } else {
    BytecodeLabels end_labels(zone());
    if (VisitLogicalAndSubExpression(first, &end_labels,
                                     coverage_slots.GetSlotFor(0))) {
      return;
    }
    HoleCheckElisionScope elider(this);
    for (size_t i = 0; i < expr->subsequent_length() - 1; ++i) {
      if (VisitLogicalAndSubExpression(expr->subsequent(i), &end_labels,
                                       coverage_slots.GetSlotFor(i + 1))) {
        return;
      }
    }
    // We have to visit the last value even if it's false, because we need its
    // actual value.
    VisitForAccumulatorValue(expr->subsequent(expr->subsequent_length() - 1));
    end_labels.Bind(builder());
  }
}

void BytecodeGenerator::VisitNullishExpression(BinaryOperation* binop) {
  Expression* left = binop->left();
  Expression* right = binop->right();

  int right_coverage_slot =
      AllocateBlockCoverageSlotIfEnabled(binop, SourceRangeKind::kRight);

  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    if (left->IsLiteralButNotNullOrUndefined() && left->ToBooleanIsTrue()) {
      builder()->Jump(test_result->NewThenLabel());
    } else if (left->IsNullOrUndefinedLiteral() &&
               right->IsNullOrUndefinedLiteral()) {
      BuildIncrementBlockCoverageCounterIfEnabled(right_coverage_slot);
      builder()->Jump(test_result->NewElseLabel());
    } else {
      VisitLogicalTest(Token::kNullish, left, right, right_coverage_slot);
    }
    test_result->SetResultConsumedByTest();
  } else {
    BytecodeLabels end_labels(zone());
    if (VisitNullishSubExpression(left, &end_labels, right_coverage_slot)) {
      return;
    }
    VisitInHoleCheckElisionScopeForAccumulatorValue(right);
    end_labels.Bind(builder());
  }
}

void BytecodeGenerator::VisitNaryNullishExpression(NaryOperation* expr) {
  Expression* first = expr->first();
  DCHECK_GT(expr->subsequent_length(), 0);

  NaryCodeCoverageSlots coverage_slots(this, expr);

  if (execution_result()->IsTest()) {
    TestResultScope* test_result = execution_result()->AsTest();
    if (first->IsLiteralButNotNullOrUndefined() && first->ToBooleanIsTrue()) {
      builder()->Jump(test_result->NewThenLabel());
    } else {
      VisitNaryLogicalTest(Token::kNullish, expr, &coverage_slots);
    }
    test_result->SetResultConsumedByTest();
  } else {
    BytecodeLabels end_labels(zone());
    if (VisitNullishSubExpression(first, &end_labels,
                                  coverage_slots.GetSlotFor(0))) {
      return;
    }
    HoleCheckElisionScope elider(this);
    for (size_t i = 0; i < expr->subsequent_length() - 1; ++i) {
      if (VisitNullishSubExpression(expr->subsequent(i), &end_labels,
                                    coverage_slots.GetSlotFor(i + 1))) {
        return;
      }
    }
    // We have to visit the last value even if it's nullish, because we need its
    // actual value.
    VisitForAccumulatorValue(expr->subsequent(expr->subsequent_length() - 1));
    end_labels.Bind(builder());
  }
}

void BytecodeGenerator::BuildNewLocalActivationContext() {
  ValueResultScope value_execution_result(this);
  Scope* scope = closure_scope();
  DCHECK_EQ(current_scope(), closure_scope());

  // Create the appropriate context.
  DCHECK(scope->is_function_scope() || scope->is_eval_scope());
  int slot_count = scope->num_heap_slots() - Context::MIN_CONTEXT_SLOTS;
  if (slot_count <= ConstructorBuiltins::MaximumFunctionContextSlots()) {
    switch (scope->scope_type()) {
      case EVAL_SCOPE:
        builder()->CreateEvalContext(scope, slot_count);
        break;
      case FUNCTION_SCOPE:
        builder()->CreateFunctionContext(scope, slot_count);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    Register arg = register_allocator()->NewRegister();
    builder()->LoadLiteral(scope).StoreAccumulatorInRegister(arg).CallRuntime(
        Runtime::kNewFunctionContext, arg);
    register_allocator()->ReleaseRegister(arg);
  }
}

void BytecodeGenerator::BuildLocalActivationContextInitialization() {
  DeclarationScope* scope = closure_scope();

  if (scope->has_this_declaration() && scope->receiver()->IsContextSlot()) {
    Variable* variable = scope->receiver();
    Register receiver(builder()->Receiver());
    // Context variable (at bottom of the context chain).
    DCHECK_EQ(0, scope->ContextChainLength(variable->scope()));
    builder()->LoadAccumulatorWithRegister(receiver).StoreContextSlot(
        execution_context()->reg(), variable, 0);
  }

  // Copy parameters into context if necessary.
  int num_parameters = scope->num_parameters();
  for (int i = 0; i < num_parameters; i++) {
    Variable* variable = scope->parameter(i);
    if (!variable->IsContextSlot()) continue;

    Register parameter(builder()->Parameter(i));
    // Context variable (at bottom of the context chain).
    DCHECK_EQ(0, scope->ContextChainLength(variable->scope()));
    builder()->LoadAccumulatorWithRegister(parameter).StoreContextSlot(
        execution_context()->reg(), variable, 0);
  }
}

void BytecodeGenerator::BuildNewLocalBlockContext(Scope* scope) {
  ValueResultScope value_execution_result(this);
  DCHECK(scope->is_block_scope());

  builder()->CreateBlockContext(scope);
}

void BytecodeGenerator::BuildNewLocalWithContext(Scope* scope) {
  ValueResultScope value_execution_result(this);

  Register extension_object = register_allocator()->NewRegister();

  builder()->ToObject(extension_object);
  builder()->CreateWithContext(extension_object, scope);

  register_allocator()->ReleaseRegister(extension_object);
}

void BytecodeGenerator::BuildNewLocalCatchContext(Scope* scope) {
  ValueResultScope value_execution_result(this);
  DCHECK(scope->catch_variable()->IsContextSlot());

  Register exception = register_allocator()->NewRegister();
  builder()->StoreAccumulatorInRegister(exception);
  builder()->CreateCatchContext(exception, scope);
  register_allocator()->ReleaseRegister(exception);
}

void BytecodeGenerator::VisitLiteralAccessor(LiteralProperty* property,
                                             Register value_out) {
  if (property == nullptr) {
    builder()->LoadNull().StoreAccumulatorInRegister(value_out);
  } else {
    VisitForRegisterValue(property->value(), value_out);
  }
}

void BytecodeGenerator::VisitArgumentsObject(Variable* variable) {
  if (variable == nullptr) return;

  DCHECK(variable->IsContextSlot() || variable->IsStackAllocated());

  // Allocate and initialize a new arguments object and assign to the
  // {arguments} variable.
  builder()->CreateArguments(closure_scope()->GetArgumentsType());
  BuildVariableAssignment(variable, Token::kAssign, HoleCheckMode::kElided);
}

void BytecodeGenerator::VisitRestArgumentsArray(Variable* rest) {
  if (rest == nullptr) return;

  // Allocate and initialize a new rest parameter and assign to the {rest}
  // variable.
  builder()->CreateArguments(CreateArgumentsType::kRestParameter);
  DCHECK(rest->IsContextSlot() || rest->IsStackAllocated());
  BuildVariableAssignment(rest, Token::kAssign, HoleCheckMode::kElided);
}

void BytecodeGenerator::VisitThisFunctionVariable(Variable* variable) {
  if (variable == nullptr) return;

  // Store the closure we were called with in the given variable.
  builder()->LoadAccumulatorWithRegister(Register::function_closure());
  BuildVariableAssignment(variable, Token::kInit, HoleCheckMode::kElided);
}

void BytecodeGenerator::VisitNewTargetVariable(Variable* variable) {
  if (variable == nullptr) return;

  // The generator resume trampoline abuses the new.target register
  // to pass in the generator object.  In ordinary calls, new.target is always
  // undefined because generator functions are non-constructible, so don't
  // assign anything to the new.target variable.
  if (IsResumableFunction(info()->literal()->kind())) return;

  if (variable->location() == VariableLocation::LOCAL) {
    // The new.target register was already assigned by entry trampoline.
    DCHECK_EQ(incoming_new_target_or_generator_.index(),
              GetRegisterForLocalVariable(variable).index());
    return;
  }

  // Store the new target we were called with in the given variable.
  builder()->LoadAccumulatorWithRegister(incoming_new_target_or_generator_);
  BuildVariableAssignment(variable, Token::kInit, HoleCheckMode::kElided);
}

void BytecodeGenerator::BuildGeneratorObjectVariableInitialization() {
  DCHECK(IsResumableFunction(info()->literal()->kind()));

  Variable* generator_object_var = closure_scope()->generator_object_var();
  RegisterAllocationScope register_scope(this);
  RegisterList args = register_allocator()->NewRegisterList(2);
  Runtime::FunctionId function_id =
      ((IsAsyncFunction(info()->literal()->kind()) &&
        !IsAsyncGeneratorFunction(info()->literal()->kind())) ||
       IsModuleWithTopLevelAwait(info()->literal()->kind()))
          ? Runtime::kInlineAsyncFunctionEnter
          : Runtime::kInlineCreateJSGeneratorObject;
  builder()
      ->MoveRegister(Register::function_closure(), args[0])
      .MoveRegister(builder()->Receiver(), args[1])
      .CallRuntime(function_id, args)
      .StoreAccumulatorInRegister(generator_object());

  if (generator_object_var->location() == VariableLocation::LOCAL) {
    // The generator object register is already set to the variable's local
    // register.
    DCHECK_EQ(generator_object().index(),
              GetRegisterForLocalVariable(generator_object_var).index());
  } else {
    BuildVariableAssignment(generator_object_var, Token::kInit,
                            HoleCheckMode::kElided);
  }
}

void BytecodeGenerator::BuildPushUndefinedIntoRegisterList(
    RegisterList* reg_list) {
  Register reg = register_allocator()->GrowRegisterList(reg_list);
  builder()->LoadUndefined().StoreAccumulatorInRegister(reg);
}

void BytecodeGenerator::BuildLoadPropertyKey(LiteralProperty* property,
                                             Register out_reg) {
  if (property->key()->IsStringLiteral()) {
    builder()
        ->LoadLiteral(property->key()->AsLiteral()->AsRawString())
        .StoreAccumulatorInRegister(out_reg);
  } else {
    VisitForAccumulatorValue(property->key());
    builder()->ToName().StoreAccumulatorInRegister(out_reg);
  }
}

int BytecodeGenerator::AllocateBlockCoverageSlotIfEnabled(
    AstNode* node, SourceRangeKind kind) {
  return (block_coverage_builder_ == nullptr)
             ? BlockCoverageBuilder::kNoCoverageArraySlot
             : block_coverage_builder_->AllocateBlockCoverageSlot(node, kind);
}

int BytecodeGenerator::AllocateNaryBlockCoverageSlotIfEnabled(
    NaryOperation* node, size_t index) {
  return (block_coverage_builder_ == nullptr)
             ? BlockCoverageBuilder::kNoCoverageArraySlot
             : block_coverage_builder_->AllocateNaryBlockCoverageSlot(node,
                                                                      index);
}

int BytecodeGenerator::AllocateConditionalChainBlockCoverageSlotIfEnabled(
    ConditionalChain* node, SourceRangeKind kind, size_t index) {
  return (block_coverage_builder_ == nullptr)
             ? BlockCoverageBuilder::kNoCoverageArraySlot
             : block_coverage_builder_
                   ->AllocateConditionalChainBlockCoverageSlot(node, kind,
                                                               index);
}

void BytecodeGenerator::BuildIncrementBlockCoverageCounterIfEnabled(
    AstNode* node, SourceRangeKind kind) {
  if (block_coverage_builder_ == nullptr) return;
  block_coverage_builder_->IncrementBlockCounter(node, kind);
}

void BytecodeGenerator::BuildIncrementBlockCoverageCounterIfEnabled(
    int coverage_array_slot) {
  if (block_coverage_builder_ != nullptr) {
    block_coverage_builder_->IncrementBlockCounter(coverage_array_slot);
  }
}

// Visits the expression |expr| and places the result in the accumulator.
BytecodeGenerator::TypeHint BytecodeGenerator::VisitForAccumulatorValue(
    Expression* expr) {
  ValueResultScope accumulator_scope(this);
  Visit(expr);
  // Record the type hint for the result of current expression in accumulator.
  const TypeHint type_hint = accumulator_scope.type_hint();
  BytecodeRegisterOptimizer* optimizer = builder()->GetRegisterOptimizer();
  if (optimizer && type_hint != TypeHint::kUnknown) {
    optimizer->SetTypeHintForAccumulator(type_hint);
  }
  return type_hint;
}

void BytecodeGenerator::VisitForAccumulatorValueOrTheHole(Expression* expr) {
  if (expr == nullptr) {
    builder()->LoadTheHole();
  } else {
    VisitForAccumulatorValue(expr);
  }
}

// Visits the expression |expr| and discards the result.
void BytecodeGenerator::VisitForEffect(Expression* expr) {
  EffectResultScope effect_scope(this);
  Visit(expr);
}

// Visits the expression |expr| and returns the register containing
// the expression result.
Register BytecodeGenerator::VisitForRegisterValue(Expression* expr) {
  VisitForAccumulatorValue(expr);
  Register result = register_allocator()->NewRegister();
  builder()->StoreAccumulatorInRegister(result);
  return result;
}

// Visits the expression |expr| and stores the expression result in
// |destination|.
void BytecodeGenerator::VisitForRegisterValue(Expression* expr,
                                              Register destination) {
  ValueResultScope register_scope(this);
  Visit(expr);
  builder()->StoreAccumulatorInRegister(destination);
}

// Visits the expression |expr| and pushes the result into a new register
// added to the end of |reg_list|.
void BytecodeGenerator::VisitAndPushIntoRegisterList(Expression* expr,
                                                     RegisterList* reg_list) {
  {
    ValueResultScope register_scope(this);
    Visit(expr);
  }
  // Grow the register list after visiting the expression to avoid reserving
  // the register across the expression evaluation, which could cause memory
  // leaks for deep expressions due to dead objects being kept alive by pointers
  // in registers.
  Register destination = register_allocator()->GrowRegisterList(reg_list);
  builder()->StoreAccumulatorInRegister(destination);
}

void BytecodeGenerator::BuildTest(ToBooleanMode mode,
                                  BytecodeLabels* then_labels,
                                  BytecodeLabels* else_labels,
                                  TestFallthrough fallthrough) {
  switch (fallthrough) {
    case TestFallthrough::kThen:
      builder()->JumpIfFalse(mode, else_labels->New());
      break;
    case TestFallthrough::kElse:
      builder()->JumpIfTrue(mode, then_labels->New());
      break;
    case TestFallthrough::kNone:
      builder()->JumpIfTrue(mode, then_labels->New());
      builder()->Jump(else_labels->New());
      break;
  }
}

// Visits the expression |expr| for testing its boolean value and jumping to the
// |then| or |other| label depending on value and short-circuit semantics
void BytecodeGenerator::VisitForTest(Expression* expr,
                                     BytecodeLabels* then_labels,
                                     BytecodeLabels* else_labels,
                                     TestFallthrough fallthrough) {
  bool result_consumed;
  TypeHint type_hint;
  {
    // To make sure that all temporary registers are returned before generating
    // jumps below, we ensure that the result scope is deleted before doing so.
    // Dead registers might be materialized otherwise.
    TestResultScope test_result(this, then_labels, else_labels, fallthrough);
    Visit(expr);
    result_consumed = test_result.result_consumed_by_test();
    type_hint = test_result.type_hint();
    // Labels and fallthrough might have been mutated, so update based on
    // TestResultScope.
    then_labels = test_result.then_labels();
    else_labels = test_result.else_labels();
    fallthrough = test_result.fallthrough();
  }
  if (!result_consumed) {
    BuildTest(ToBooleanModeFromTypeHint(type_hint), then_labels, else_labels,
              fallthrough);
  }
}

// Visits the expression |expr| for testing its nullish value and jumping to the
// |then| or |other| label depending on value and short-circuit semantics
void BytecodeGenerator::VisitForNullishTest(Expression* expr,
                                            BytecodeLabels* then_labels,
                                            BytecodeLabels* test_next_labels,
                                            BytecodeLabels* else_labels) {
  // Nullish short circuits on undefined or null, otherwise we fall back to
  // BuildTest with no fallthrough.
  // TODO(joshualitt): We should do this in a TestResultScope.
  TypeHint type_hint = VisitForAccumulatorValue(expr);
  ToBooleanMode mode = ToBooleanModeFromTypeHint(type_hint)
"""


```