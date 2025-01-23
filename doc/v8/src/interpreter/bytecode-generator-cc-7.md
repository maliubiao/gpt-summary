Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/interpreter/bytecode-generator.cc`. I need to identify the key actions performed by this code. The code seems to be related to generating bytecode for various JavaScript language constructs, specifically focusing on asynchronous operations (`await`, `yield*`), exception handling (`throw`), property access, and function calls (including super calls).

Here's a breakdown of the thought process:

1. **Identify the Core Class:** The code is part of the `BytecodeGenerator` class. This immediately suggests its primary function is generating bytecode.

2. **Analyze Key Methods:**  Scan the provided code for the most important methods. Methods starting with `Build` or `Visit` are good candidates.

3. **Group Functionality by Keywords:** Look for keywords that indicate specific JavaScript features:
    * `Await`:  This clearly deals with the `await` keyword in async functions.
    * `Yield`: The `BuildYieldStar` method handles `yield*`.
    * `Throw`:  The `VisitThrow` method handles `throw` statements.
    * `PropertyLoad`:  Methods like `VisitPropertyLoad`, `BuildLoadNamedProperty`, `BuildLoadKeyedProperty`, etc., are about accessing object properties. The handling of super properties and private properties is also evident.
    * `Call`:  The `VisitCall` and `VisitCallSuper` methods manage function and super constructor calls. The handling of spread syntax within calls is also apparent.
    * `OptionalChain`: The `BuildOptionalChain` and related methods handle the optional chaining operator (`?.`).

4. **Understand the Context:** The code uses terms like "accumulator," "register," "bytecode label," and "feedback slot." This indicates it's working at a low level, generating instructions for the V8 virtual machine.

5. **Consider Control Flow:** Pay attention to bytecode labels (`BytecodeLabel`) and conditional jumps (`JumpIfTrue`, `JumpIfFalse`). This reveals how the bytecode generator handles different execution paths.

6. **Identify Interactions with Runtime:**  Look for calls to `Runtime::k...`. These represent calls to built-in V8 functions to perform actions that cannot be directly expressed in bytecode. Examples include `Runtime::kInlineAsyncGeneratorAwait`, `Runtime::kThrowIteratorResultNotAnObject`, `Runtime::kLoadFromSuper`, etc.

7. **Look for Error Handling:** The presence of `Throw()` and calls to runtime functions that create error objects (e.g., `Runtime::kNewTypeError`) indicates how the bytecode generator handles error conditions.

8. **Address Specific Questions:**
    * **`.tq` files:** The prompt asks about `.tq` files. The code is `.cc`, so it's standard C++.
    * **JavaScript Examples:**  Think about simple JavaScript code snippets that would trigger the functionality of the methods identified.
    * **Logic Inference:**  For methods with conditional logic, consider simple input scenarios and their expected outcome.
    * **Common Programming Errors:** Think about typical errors developers make that these bytecode generation patterns might relate to (e.g., calling methods on null/undefined, incorrect use of `super`).

9. **Structure the Summary:** Organize the findings logically. Start with the core purpose, then break down functionality by JavaScript construct. Address the specific constraints (JavaScript examples, logic inference, common errors) for each area.

10. **Review and Refine:** Read through the generated summary, ensuring it's accurate, comprehensive, and addresses all aspects of the user's request. Make sure the JavaScript examples are relevant and the logic inferences are clear.

Applying this process led to the summary provided in the initial example answer. The key was to dissect the C++ code based on the JavaScript features it's designed to handle and then synthesize that information into a coherent explanation.好的，我们来分析一下 `v8/src/interpreter/bytecode-generator.cc` 代码片段的功能。

**核心功能归纳**

这个代码片段是 V8 引擎的字节码生成器的一部分，负责将抽象语法树 (AST) 中的特定 JavaScript 语法结构转换为 V8 解释器可以执行的字节码指令。 具体来说，这部分代码处理了以下关键的 JavaScript 特性：

1. **异步操作 (Async/Await):**
   - `BuildAwait()`:  生成处理 `await` 表达式的字节码。它会暂停异步函数的执行，等待 promise 决议，并在恢复时根据决议状态继续执行。
   - `VisitAwait()`:  访问 `Await` 节点，并为其生成相应的字节码。

2. **生成器 (Generators) 和 `yield*` 表达式:**
   - `BuildYieldStar()`:  处理 `yield*` 表达式，允许一个生成器委托给另一个可迭代对象（包括其他生成器）。它负责迭代被委托的对象，并根据其结果决定生成器的后续行为（返回、抛出异常或产生值）。

3. **异常处理 (`throw`):**
   - `VisitThrow()`:  访问 `Throw` 节点，并生成抛出异常的字节码指令。

4. **属性访问 (Property Access):**
   - `VisitPropertyLoad()`:  处理属性读取操作，根据属性的类型（命名、键值、super 属性、私有属性等）生成不同的字节码指令。
   - `BuildLoadNamedProperty()`、`BuildLoadKeyedProperty()`: 生成加载命名和键值属性的字节码。
   - `VisitNamedSuperPropertyLoad()`、`VisitKeyedSuperPropertyLoad()`:  处理 `super` 关键字的属性访问。
   - 处理私有属性的访问 (`BuildPrivateBrandCheck`, `BuildPrivateGetterAccess`, `BuildPrivateSetterAccess`, `BuildPrivateMethodIn`)，包括静态和实例私有成员。

5. **可选链 (`?.`):**
   - `BuildOptionalChain()`:  为可选链操作生成字节码，确保在遇到 `null` 或 `undefined` 时不会抛出错误，而是返回 `undefined`。
   - `VisitOptionalChain()`: 访问 `OptionalChain` 节点并生成字节码。

6. **函数调用 (Function Calls):**
   - `VisitCall()`:  处理函数调用，根据不同的调用类型（普通调用、方法调用、super 调用、`eval` 调用等）生成不同的字节码。
   - `VisitCallSuper()`: 处理 `super()` 调用，包括构造函数的调用。

**关于文件类型和 JavaScript 关系**

- **文件类型:** 就像您观察到的，`v8/src/interpreter/bytecode-generator.cc` 的确是以 `.cc` 结尾，这意味着它是 **C++** 源代码文件，而不是 Torque (`.tq`) 文件。Torque 是一种 V8 使用的领域特定语言，用于定义运行时函数的实现。

- **与 JavaScript 的关系:**  这个文件的核心功能就是 **将 JavaScript 代码转化为 V8 虚拟机可以理解和执行的指令**。它直接参与了 JavaScript 代码的编译过程。

**JavaScript 示例**

以下是一些 JavaScript 示例，展示了这段 C++ 代码处理的功能：

```javascript
// 异步函数和 await
async function myFunction() {
  console.log("开始");
  const result = await someAsyncOperation();
  console.log("结束", result);
  return result;
}

// 生成器和 yield*
function* generatorFunction() {
  yield 1;
  yield* anotherGenerator(); // 委托给另一个生成器
  yield 4;
}

function* anotherGenerator() {
  yield 2;
  yield 3;
}

// 抛出异常
function throwError() {
  throw new Error("Something went wrong!");
}

// 属性访问
const obj = { a: 1, b: 2 };
console.log(obj.a); // 命名属性访问
const key = 'b';
console.log(obj[key]); // 键值属性访问

class Parent {
  parentMethod() { return "parent"; }
}
class Child extends Parent {
  childMethod() {
    return super.parentMethod(); // super 属性访问
  }
}

class MyClass {
  #privateField = 10;
  get #privateGetter() { return this.#privateField; }
  myMethod() {
    console.log(this.#privateGetter); // 私有属性访问
  }
}

// 可选链
const myObj = { nested: { value: 42 } };
const value = myObj?.nested?.value; // 使用可选链避免 null/undefined 错误

// 函数调用
function add(x, y) {
  return x + y;
}
add(5, 3); // 普通函数调用

const myObject = {
  myMethod(val) { return val * 2; }
};
myObject.myMethod(10); // 方法调用

class Base {
  constructor(val) {
    this.value = val;
  }
}
class Derived extends Base {
  constructor() {
    super(100); // super() 构造函数调用
  }
}
```

**代码逻辑推理 (假设输入与输出)**

假设我们有以下简单的异步函数：

```javascript
async function testAwait() {
  return await Promise.resolve(5);
}
```

**假设输入 (AST 节点):**  `Await` 表达式的 AST 节点，其中包含对 `Promise.resolve(5)` 表达式的引用。

**代码逻辑推理 (针对 `BuildAwait()`):**

1. **`VisitForAccumulatorValue(expr->expression())`:**  首先，会生成字节码来执行 `Promise.resolve(5)`，并将结果（一个 promise）放入累加器 (accumulator)。
2. **`BuildAwait(expr->position())`:**  调用 `BuildAwait()`，该函数会生成以下（简化的）字节码序列：
   - **`CallRuntime(kInlineAsyncFunctionAwait, ...)`:** 调用 V8 运行时函数，将当前的生成器对象和累加器中的 promise 传递给它。运行时函数会处理 promise 的等待。
   - **`BuildSuspendPoint(position)`:** 生成一个暂停点，指示解释器暂停当前函数的执行。
   - **`CallRuntime(kInlineGeneratorGetResumeMode, ...)`:** 当 promise 决议后恢复执行时，会调用此运行时函数来获取恢复模式（例如，是正常决议还是拒绝）。
   - **条件分支:** 根据恢复模式，如果 promise 正常决议，累加器中会放入决议的值；如果 promise 被拒绝，则会抛出异常。

**假设输出 (部分字节码 - 简化表示):**

```
LdaGlobal  [Promise]
LdaProperty  [resolve]
LdaSmi [5]
CallRuntime [PromiseResolve]  // Promise.resolve(5)
CallRuntime [InlineAsyncFunctionAwait]
SuspendGenerator
CallRuntime [InlineGeneratorGetResumeMode]
// ... 根据恢复模式进行分支 ...
```

**用户常见的编程错误**

1. **在非异步函数中使用 `await`:**  这是常见的语法错误，会导致 `SyntaxError`。字节码生成器在遇到这种情况时会抛出错误，阻止生成无效的字节码。

   ```javascript
   function syncFunction() {
     // 错误：await 只能在 async 函数中使用
     const result = await somePromise;
   }
   ```

2. **在 `yield*` 中使用不可迭代的对象:**  `yield*` 期望操作数是可迭代的。如果传入非可迭代对象，运行时会抛出 `TypeError`。

   ```javascript
   function* myGenerator() {
     yield* 123; // 错误：数字不可迭代
   }
   ```

3. **访问 `null` 或 `undefined` 的属性而没有进行检查:**  这会导致 `TypeError`。可选链运算符 (`?.`) 就是为了避免这种错误而引入的，而 `BuildOptionalChain()` 就是处理这种情况的。

   ```javascript
   const obj = null;
   // 可能会抛出错误，除非使用可选链
   console.log(obj.property);
   console.log(obj?.property);
   ```

4. **不正确地使用 `super`:**  例如，在构造函数之外调用 `super()`，或者在静态方法中使用 `super` 访问实例成员，都会导致错误。

   ```javascript
   class BadChild extends Parent {
     method() {
       super.parentMethod(); // 正确
     }
   }

   class ReallyBadChild extends Parent {
     method() {
       // 错误：在构造函数之外不能直接调用 super()
       super();
     }
   }
   ```

**总结 `v8/src/interpreter/bytecode-generator.cc` 的功能 (针对第 8 部分)**

在提供的代码片段中，`v8/src/interpreter/bytecode-generator.cc` 的主要功能是 **将 JavaScript 中与异步操作、生成器委托、异常抛出、属性访问（包括私有和 super 属性）、可选链以及函数调用相关的语法结构转换为解释器可以执行的字节码指令**。  这部分代码确保了 V8 能够正确地执行这些关键的 JavaScript 语言特性。它还包含了处理一些常见的编程错误和边界情况的逻辑。

请注意，这只是字节码生成器的一部分功能，整个文件和相关的模块还负责处理其他各种 JavaScript 语法结构。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
on.
        BuildAwait(expr->position());
      }

      // Check that output is an object.
      BytecodeLabel check_if_done;
      builder()
          ->StoreAccumulatorInRegister(output)
          .JumpIfJSReceiver(&check_if_done)
          .CallRuntime(Runtime::kThrowIteratorResultNotAnObject, output);

      builder()->Bind(&check_if_done);
      // Break once output.done is true.
      builder()->LoadNamedProperty(
          output, ast_string_constants()->done_string(),
          feedback_index(feedback_spec()->AddLoadICSlot()));

      loop_builder.BreakIfTrue(ToBooleanMode::kConvertToBoolean);

      // Suspend the current generator.
      if (iterator_type == IteratorType::kNormal) {
        builder()->LoadAccumulatorWithRegister(output);
      } else {
        RegisterAllocationScope inner_register_scope(this);
        DCHECK_EQ(iterator_type, IteratorType::kAsync);
        // If generatorKind is async, perform
        // AsyncGeneratorResolve(output.value, /* done = */ false), which will
        // resolve the current AsyncGeneratorRequest's promise with
        // output.value.
        builder()->LoadNamedProperty(
            output, ast_string_constants()->value_string(),
            feedback_index(feedback_spec()->AddLoadICSlot()));

        RegisterList args = register_allocator()->NewRegisterList(3);
        builder()
            ->MoveRegister(generator_object(), args[0])  // generator
            .StoreAccumulatorInRegister(args[1])         // value
            .LoadFalse()
            .StoreAccumulatorInRegister(args[2])  // done
            .CallRuntime(Runtime::kInlineAsyncGeneratorResolve, args);
      }

      BuildSuspendPoint(expr->position());
      builder()->StoreAccumulatorInRegister(input);
      builder()
          ->CallRuntime(Runtime::kInlineGeneratorGetResumeMode,
                        generator_object())
          .StoreAccumulatorInRegister(resume_mode);

      loop_builder.BindContinueTarget();
    }
  }

  // Decide if we trigger a return or if the yield* expression should just
  // produce a value.
  BytecodeLabel completion_is_output_value;
  Register output_value = register_allocator()->NewRegister();
  builder()
      ->LoadNamedProperty(output, ast_string_constants()->value_string(),
                          feedback_index(feedback_spec()->AddLoadICSlot()))
      .StoreAccumulatorInRegister(output_value)
      .LoadLiteral(Smi::FromInt(JSGeneratorObject::kReturn))
      .CompareReference(resume_mode)
      .JumpIfFalse(ToBooleanMode::kAlreadyBoolean, &completion_is_output_value)
      .LoadAccumulatorWithRegister(output_value);
  if (iterator_type == IteratorType::kAsync) {
    execution_control()->AsyncReturnAccumulator(kNoSourcePosition);
  } else {
    execution_control()->ReturnAccumulator(kNoSourcePosition);
  }

  builder()->Bind(&completion_is_output_value);
  BuildIncrementBlockCoverageCounterIfEnabled(expr,
                                              SourceRangeKind::kContinuation);
  builder()->LoadAccumulatorWithRegister(output_value);
}

void BytecodeGenerator::BuildAwait(int position) {
  // Rather than HandlerTable::UNCAUGHT, async functions use
  // HandlerTable::ASYNC_AWAIT to communicate that top-level exceptions are
  // transformed into promise rejections. This is necessary to prevent emitting
  // multiple debug events for the same uncaught exception. There is no point
  // in the body of an async function where catch prediction is
  // HandlerTable::UNCAUGHT.
  DCHECK(catch_prediction() != HandlerTable::UNCAUGHT ||
         info()->scope()->is_repl_mode_scope());

  {
    // Await(operand) and suspend.
    RegisterAllocationScope register_scope(this);

    Runtime::FunctionId await_intrinsic_id;
    if (IsAsyncGeneratorFunction(function_kind())) {
      await_intrinsic_id = Runtime::kInlineAsyncGeneratorAwait;
    } else {
      await_intrinsic_id = Runtime::kInlineAsyncFunctionAwait;
    }
    RegisterList args = register_allocator()->NewRegisterList(2);
    builder()
        ->MoveRegister(generator_object(), args[0])
        .StoreAccumulatorInRegister(args[1])
        .CallRuntime(await_intrinsic_id, args);
  }

  BuildSuspendPoint(position);

  Register input = register_allocator()->NewRegister();
  Register resume_mode = register_allocator()->NewRegister();

  // Now dispatch on resume mode.
  BytecodeLabel resume_next;
  builder()
      ->StoreAccumulatorInRegister(input)
      .CallRuntime(Runtime::kInlineGeneratorGetResumeMode, generator_object())
      .StoreAccumulatorInRegister(resume_mode)
      .LoadLiteral(Smi::FromInt(JSGeneratorObject::kNext))
      .CompareReference(resume_mode)
      .JumpIfTrue(ToBooleanMode::kAlreadyBoolean, &resume_next);

  // Resume with "throw" completion (rethrow the received value).
  // TODO(leszeks): Add a debug-only check that the accumulator is
  // JSGeneratorObject::kThrow.
  builder()->LoadAccumulatorWithRegister(input).ReThrow();

  // Resume with next.
  builder()->Bind(&resume_next);
  builder()->LoadAccumulatorWithRegister(input);
}

void BytecodeGenerator::VisitAwait(Await* expr) {
  builder()->SetExpressionPosition(expr);
  VisitForAccumulatorValue(expr->expression());
  BuildAwait(expr->position());
  BuildIncrementBlockCoverageCounterIfEnabled(expr,
                                              SourceRangeKind::kContinuation);
}

void BytecodeGenerator::VisitThrow(Throw* expr) {
  AllocateBlockCoverageSlotIfEnabled(expr, SourceRangeKind::kContinuation);
  VisitForAccumulatorValue(expr->exception());
  builder()->SetExpressionPosition(expr);
  builder()->Throw();
}

void BytecodeGenerator::VisitPropertyLoad(Register obj, Property* property) {
  if (property->is_optional_chain_link()) {
    DCHECK_NOT_NULL(optional_chaining_null_labels_);
    int right_range =
        AllocateBlockCoverageSlotIfEnabled(property, SourceRangeKind::kRight);
    builder()->LoadAccumulatorWithRegister(obj).JumpIfUndefinedOrNull(
        optional_chaining_null_labels_->New());
    BuildIncrementBlockCoverageCounterIfEnabled(right_range);
  }

  AssignType property_kind = Property::GetAssignType(property);

  switch (property_kind) {
    case NON_PROPERTY:
      UNREACHABLE();
    case NAMED_PROPERTY: {
      builder()->SetExpressionPosition(property);
      const AstRawString* name =
          property->key()->AsLiteral()->AsRawPropertyName();
      BuildLoadNamedProperty(property->obj(), obj, name);
      break;
    }
    case KEYED_PROPERTY: {
      VisitForAccumulatorValue(property->key());
      builder()->SetExpressionPosition(property);
      BuildLoadKeyedProperty(obj, feedback_spec()->AddKeyedLoadICSlot());
      break;
    }
    case NAMED_SUPER_PROPERTY:
      VisitNamedSuperPropertyLoad(property, Register::invalid_value());
      break;
    case KEYED_SUPER_PROPERTY:
      VisitKeyedSuperPropertyLoad(property, Register::invalid_value());
      break;
    case PRIVATE_SETTER_ONLY: {
      BuildPrivateBrandCheck(property, obj);
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateGetterAccess,
                                 property);
      break;
    }
    case PRIVATE_GETTER_ONLY:
    case PRIVATE_GETTER_AND_SETTER: {
      Register key = VisitForRegisterValue(property->key());
      BuildPrivateBrandCheck(property, obj);
      BuildPrivateGetterAccess(obj, key);
      break;
    }
    case PRIVATE_METHOD: {
      BuildPrivateBrandCheck(property, obj);
      // In the case of private methods, property->key() is the function to be
      // loaded (stored in a context slot), so load this directly.
      VisitForAccumulatorValue(property->key());
      break;
    }
    case PRIVATE_DEBUG_DYNAMIC: {
      BuildPrivateDebugDynamicGet(property, obj);
      break;
    }
  }
}

void BytecodeGenerator::BuildPrivateDebugDynamicGet(Property* property,
                                                    Register obj) {
  RegisterAllocationScope scope(this);
  RegisterList args = register_allocator()->NewRegisterList(2);

  Variable* private_name = property->key()->AsVariableProxy()->var();
  builder()
      ->MoveRegister(obj, args[0])
      .LoadLiteral(private_name->raw_name())
      .StoreAccumulatorInRegister(args[1])
      .CallRuntime(Runtime::kGetPrivateMember, args);
}

void BytecodeGenerator::BuildPrivateDebugDynamicSet(Property* property,
                                                    Register obj,
                                                    Register value) {
  RegisterAllocationScope scope(this);
  RegisterList args = register_allocator()->NewRegisterList(3);

  Variable* private_name = property->key()->AsVariableProxy()->var();
  builder()
      ->MoveRegister(obj, args[0])
      .LoadLiteral(private_name->raw_name())
      .StoreAccumulatorInRegister(args[1])
      .MoveRegister(value, args[2])
      .CallRuntime(Runtime::kSetPrivateMember, args);
}

void BytecodeGenerator::BuildPrivateGetterAccess(Register object,
                                                 Register accessor_pair) {
  RegisterAllocationScope scope(this);
  Register accessor = register_allocator()->NewRegister();
  RegisterList args = register_allocator()->NewRegisterList(1);

  builder()
      ->CallRuntime(Runtime::kLoadPrivateGetter, accessor_pair)
      .StoreAccumulatorInRegister(accessor)
      .MoveRegister(object, args[0])
      .CallProperty(accessor, args,
                    feedback_index(feedback_spec()->AddCallICSlot()));
}

void BytecodeGenerator::BuildPrivateSetterAccess(Register object,
                                                 Register accessor_pair,
                                                 Register value) {
  RegisterAllocationScope scope(this);
  Register accessor = register_allocator()->NewRegister();
  RegisterList args = register_allocator()->NewRegisterList(2);

  builder()
      ->CallRuntime(Runtime::kLoadPrivateSetter, accessor_pair)
      .StoreAccumulatorInRegister(accessor)
      .MoveRegister(object, args[0])
      .MoveRegister(value, args[1])
      .CallProperty(accessor, args,
                    feedback_index(feedback_spec()->AddCallICSlot()));
}

void BytecodeGenerator::BuildPrivateMethodIn(Variable* private_name,
                                             Expression* object_expression) {
  DCHECK(IsPrivateMethodOrAccessorVariableMode(private_name->mode()));
  ClassScope* scope = private_name->scope()->AsClassScope();
  if (private_name->is_static()) {
    // For static private methods, "#privatemethod in ..." only returns true for
    // the class constructor.
    if (scope->class_variable() == nullptr) {
      // Can only happen via the debugger. See comment in
      // BuildPrivateBrandCheck.
      RegisterAllocationScope register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->LoadLiteral(Smi::FromEnum(
              MessageTemplate::
                  kInvalidUnusedPrivateStaticMethodAccessedByDebugger))
          .StoreAccumulatorInRegister(args[0])
          .LoadLiteral(private_name->raw_name())
          .StoreAccumulatorInRegister(args[1])
          .CallRuntime(Runtime::kNewError, args)
          .Throw();
    } else {
      VisitForAccumulatorValue(object_expression);
      Register object = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(object);

      BytecodeLabel is_object;
      builder()->JumpIfJSReceiver(&is_object);

      RegisterList args = register_allocator()->NewRegisterList(3);
      builder()
          ->StoreAccumulatorInRegister(args[2])
          .LoadLiteral(Smi::FromEnum(MessageTemplate::kInvalidInOperatorUse))
          .StoreAccumulatorInRegister(args[0])
          .LoadLiteral(private_name->raw_name())
          .StoreAccumulatorInRegister(args[1])
          .CallRuntime(Runtime::kNewTypeError, args)
          .Throw();

      builder()->Bind(&is_object);
      BuildVariableLoadForAccumulatorValue(scope->class_variable(),
                                           HoleCheckMode::kElided);
      builder()->CompareReference(object);
    }
  } else {
    BuildVariableLoadForAccumulatorValue(scope->brand(),
                                         HoleCheckMode::kElided);
    Register brand = register_allocator()->NewRegister();
    builder()->StoreAccumulatorInRegister(brand);

    VisitForAccumulatorValue(object_expression);
    builder()->SetExpressionPosition(object_expression);

    FeedbackSlot slot = feedback_spec()->AddKeyedHasICSlot();
    builder()->CompareOperation(Token::kIn, brand, feedback_index(slot));
    execution_result()->SetResultIsBoolean();
  }
}

void BytecodeGenerator::BuildPrivateBrandCheck(Property* property,
                                               Register object) {
  Variable* private_name = property->key()->AsVariableProxy()->var();
  DCHECK(IsPrivateMethodOrAccessorVariableMode(private_name->mode()));
  ClassScope* scope = private_name->scope()->AsClassScope();
  builder()->SetExpressionPosition(property);
  if (private_name->is_static()) {
    // For static private methods, the only valid receiver is the class.
    // Load the class constructor.
    if (scope->class_variable() == nullptr) {
      // If the static private method has not been used used in source
      // code (either explicitly or through the presence of eval), but is
      // accessed by the debugger at runtime, reference to the class variable
      // is not available since it was not be context-allocated. Therefore we
      // can't build a branch check, and throw an ReferenceError as if the
      // method was optimized away.
      // TODO(joyee): get a reference to the class constructor through
      // something other than scope->class_variable() in this scenario.
      RegisterAllocationScope register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->LoadLiteral(Smi::FromEnum(
              MessageTemplate::
                  kInvalidUnusedPrivateStaticMethodAccessedByDebugger))
          .StoreAccumulatorInRegister(args[0])
          .LoadLiteral(private_name->raw_name())
          .StoreAccumulatorInRegister(args[1])
          .CallRuntime(Runtime::kNewError, args)
          .Throw();
    } else {
      BuildVariableLoadForAccumulatorValue(scope->class_variable(),
                                           HoleCheckMode::kElided);
      BytecodeLabel return_check;
      builder()->CompareReference(object).JumpIfTrue(
          ToBooleanMode::kAlreadyBoolean, &return_check);
      const AstRawString* name = scope->class_variable()->raw_name();
      RegisterAllocationScope register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->LoadLiteral(
              Smi::FromEnum(MessageTemplate::kInvalidPrivateBrandStatic))
          .StoreAccumulatorInRegister(args[0])
          .LoadLiteral(name)
          .StoreAccumulatorInRegister(args[1])
          .CallRuntime(Runtime::kNewTypeError, args)
          .Throw();
      builder()->Bind(&return_check);
    }
  } else {
    BuildVariableLoadForAccumulatorValue(scope->brand(),
                                         HoleCheckMode::kElided);
    builder()->LoadKeyedProperty(
        object, feedback_index(feedback_spec()->AddKeyedLoadICSlot()));
  }
}

void BytecodeGenerator::VisitPropertyLoadForRegister(Register obj,
                                                     Property* expr,
                                                     Register destination) {
  ValueResultScope result_scope(this);
  VisitPropertyLoad(obj, expr);
  builder()->StoreAccumulatorInRegister(destination);
}

void BytecodeGenerator::VisitNamedSuperPropertyLoad(Property* property,
                                                    Register opt_receiver_out) {
  RegisterAllocationScope register_scope(this);
  if (v8_flags.super_ic) {
    Register receiver = register_allocator()->NewRegister();
    BuildThisVariableLoad();
    builder()->StoreAccumulatorInRegister(receiver);
    BuildVariableLoad(
        property->obj()->AsSuperPropertyReference()->home_object()->var(),
        HoleCheckMode::kElided);
    builder()->SetExpressionPosition(property);
    auto name = property->key()->AsLiteral()->AsRawPropertyName();
    FeedbackSlot slot = GetCachedLoadSuperICSlot(name);
    builder()->LoadNamedPropertyFromSuper(receiver, name, feedback_index(slot));
    if (opt_receiver_out.is_valid()) {
      builder()->MoveRegister(receiver, opt_receiver_out);
    }
  } else {
    RegisterList args = register_allocator()->NewRegisterList(3);
    BuildThisVariableLoad();
    builder()->StoreAccumulatorInRegister(args[0]);
    BuildVariableLoad(
        property->obj()->AsSuperPropertyReference()->home_object()->var(),
        HoleCheckMode::kElided);
    builder()->StoreAccumulatorInRegister(args[1]);
    builder()->SetExpressionPosition(property);
    builder()
        ->LoadLiteral(property->key()->AsLiteral()->AsRawPropertyName())
        .StoreAccumulatorInRegister(args[2])
        .CallRuntime(Runtime::kLoadFromSuper, args);

    if (opt_receiver_out.is_valid()) {
      builder()->MoveRegister(args[0], opt_receiver_out);
    }
  }
}

void BytecodeGenerator::VisitKeyedSuperPropertyLoad(Property* property,
                                                    Register opt_receiver_out) {
  RegisterAllocationScope register_scope(this);
  RegisterList args = register_allocator()->NewRegisterList(3);
  BuildThisVariableLoad();
  builder()->StoreAccumulatorInRegister(args[0]);
  BuildVariableLoad(
      property->obj()->AsSuperPropertyReference()->home_object()->var(),
      HoleCheckMode::kElided);
  builder()->StoreAccumulatorInRegister(args[1]);
  VisitForRegisterValue(property->key(), args[2]);

  builder()->SetExpressionPosition(property);
  builder()->CallRuntime(Runtime::kLoadKeyedFromSuper, args);

  if (opt_receiver_out.is_valid()) {
    builder()->MoveRegister(args[0], opt_receiver_out);
  }
}

template <typename ExpressionFunc>
void BytecodeGenerator::BuildOptionalChain(ExpressionFunc expression_func) {
  BytecodeLabel done;
  OptionalChainNullLabelScope label_scope(this);
  // Use the same scope for the entire optional chain, as links earlier in the
  // chain dominate later links, linearly.
  HoleCheckElisionScope elider(this);
  expression_func();
  builder()->Jump(&done);
  label_scope.labels()->Bind(builder());
  builder()->LoadUndefined();
  builder()->Bind(&done);
}

void BytecodeGenerator::VisitOptionalChain(OptionalChain* expr) {
  BuildOptionalChain([&]() { VisitForAccumulatorValue(expr->expression()); });
}

void BytecodeGenerator::VisitProperty(Property* expr) {
  AssignType property_kind = Property::GetAssignType(expr);
  if (property_kind != NAMED_SUPER_PROPERTY &&
      property_kind != KEYED_SUPER_PROPERTY) {
    Register obj = VisitForRegisterValue(expr->obj());
    VisitPropertyLoad(obj, expr);
  } else {
    VisitPropertyLoad(Register::invalid_value(), expr);
  }
}

void BytecodeGenerator::VisitArguments(const ZonePtrList<Expression>* args,
                                       RegisterList* arg_regs) {
  // Visit arguments.
  builder()->UpdateMaxArguments(static_cast<uint16_t>(args->length()));
  for (int i = 0; i < static_cast<int>(args->length()); i++) {
    VisitAndPushIntoRegisterList(args->at(i), arg_regs);
  }
}

void BytecodeGenerator::VisitCall(Call* expr) {
  Expression* callee_expr = expr->expression();
  Call::CallType call_type = expr->GetCallType();

  if (call_type == Call::SUPER_CALL) {
    return VisitCallSuper(expr);
  }

  // We compile the call differently depending on the presence of spreads and
  // their positions.
  //
  // If there is only one spread and it is the final argument, there is a
  // special CallWithSpread bytecode.
  //
  // If there is a non-final spread, we rewrite calls like
  //     callee(1, ...x, 2)
  // to
  //     %reflect_apply(callee, receiver, [1, ...x, 2])
  const Call::SpreadPosition spread_position = expr->spread_position();

  // Grow the args list as we visit receiver / arguments to avoid allocating all
  // the registers up-front. Otherwise these registers are unavailable during
  // receiver / argument visiting and we can end up with memory leaks due to
  // registers keeping objects alive.
  RegisterList args = register_allocator()->NewGrowableRegisterList();

  // The callee is the first register in args for ease of calling %reflect_apply
  // if we have a non-final spread. For all other cases it is popped from args
  // before emitting the call below.
  Register callee = register_allocator()->GrowRegisterList(&args);

  bool implicit_undefined_receiver = false;

  // TODO(petermarshall): We have a lot of call bytecodes that are very similar,
  // see if we can reduce the number by adding a separate argument which
  // specifies the call type (e.g., property, spread, tailcall, etc.).

  // Prepare the callee and the receiver to the function call. This depends on
  // the semantics of the underlying call type.
  switch (call_type) {
    case Call::NAMED_PROPERTY_CALL:
    case Call::KEYED_PROPERTY_CALL:
    case Call::PRIVATE_CALL: {
      Property* property = callee_expr->AsProperty();
      VisitAndPushIntoRegisterList(property->obj(), &args);
      VisitPropertyLoadForRegister(args.last_register(), property, callee);
      break;
    }
    case Call::GLOBAL_CALL: {
      // Receiver is undefined for global calls.
      if (spread_position == Call::kNoSpread) {
        implicit_undefined_receiver = true;
      } else {
        // TODO(leszeks): There's no special bytecode for tail calls or spread
        // calls with an undefined receiver, so just push undefined ourselves.
        BuildPushUndefinedIntoRegisterList(&args);
      }
      // Load callee as a global variable.
      VariableProxy* proxy = callee_expr->AsVariableProxy();
      BuildVariableLoadForAccumulatorValue(proxy->var(),
                                           proxy->hole_check_mode());
      builder()->StoreAccumulatorInRegister(callee);
      break;
    }
    case Call::WITH_CALL: {
      Register receiver = register_allocator()->GrowRegisterList(&args);
      DCHECK(callee_expr->AsVariableProxy()->var()->IsLookupSlot());
      {
        RegisterAllocationScope inner_register_scope(this);
        Register name = register_allocator()->NewRegister();

        // Call %LoadLookupSlotForCall to get the callee and receiver.
        RegisterList result_pair = register_allocator()->NewRegisterList(2);
        Variable* variable = callee_expr->AsVariableProxy()->var();
        builder()
            ->LoadLiteral(variable->raw_name())
            .StoreAccumulatorInRegister(name)
            .CallRuntimeForPair(Runtime::kLoadLookupSlotForCall, name,
                                result_pair)
            .MoveRegister(result_pair[0], callee)
            .MoveRegister(result_pair[1], receiver);
      }
      break;
    }
    case Call::OTHER_CALL: {
      // Receiver is undefined for other calls.
      if (spread_position == Call::kNoSpread) {
        implicit_undefined_receiver = true;
      } else {
        // TODO(leszeks): There's no special bytecode for tail calls or spread
        // calls with an undefined receiver, so just push undefined ourselves.
        BuildPushUndefinedIntoRegisterList(&args);
      }
      VisitForRegisterValue(callee_expr, callee);
      break;
    }
    case Call::NAMED_SUPER_PROPERTY_CALL: {
      Register receiver = register_allocator()->GrowRegisterList(&args);
      Property* property = callee_expr->AsProperty();
      VisitNamedSuperPropertyLoad(property, receiver);
      builder()->StoreAccumulatorInRegister(callee);
      break;
    }
    case Call::KEYED_SUPER_PROPERTY_CALL: {
      Register receiver = register_allocator()->GrowRegisterList(&args);
      Property* property = callee_expr->AsProperty();
      VisitKeyedSuperPropertyLoad(property, receiver);
      builder()->StoreAccumulatorInRegister(callee);
      break;
    }
    case Call::NAMED_OPTIONAL_CHAIN_PROPERTY_CALL:
    case Call::KEYED_OPTIONAL_CHAIN_PROPERTY_CALL:
    case Call::PRIVATE_OPTIONAL_CHAIN_CALL: {
      OptionalChain* chain = callee_expr->AsOptionalChain();
      Property* property = chain->expression()->AsProperty();
      BuildOptionalChain([&]() {
        VisitAndPushIntoRegisterList(property->obj(), &args);
        VisitPropertyLoad(args.last_register(), property);
      });
      builder()->StoreAccumulatorInRegister(callee);
      break;
    }
    case Call::SUPER_CALL:
      UNREACHABLE();
  }

  if (expr->is_optional_chain_link()) {
    DCHECK_NOT_NULL(optional_chaining_null_labels_);
    int right_range =
        AllocateBlockCoverageSlotIfEnabled(expr, SourceRangeKind::kRight);
    builder()->LoadAccumulatorWithRegister(callee).JumpIfUndefinedOrNull(
        optional_chaining_null_labels_->New());
    BuildIncrementBlockCoverageCounterIfEnabled(right_range);
  }

  int receiver_arg_count = -1;
  if (spread_position == Call::kHasNonFinalSpread) {
    // If we're building %reflect_apply, build the array literal and put it in
    // the 3rd argument.
    DCHECK(!implicit_undefined_receiver);
    DCHECK_EQ(args.register_count(), 2);
    BuildCreateArrayLiteral(expr->arguments(), nullptr);
    builder()->StoreAccumulatorInRegister(
        register_allocator()->GrowRegisterList(&args));
  } else {
    // If we're not building %reflect_apply and don't need to build an array
    // literal, pop the callee and evaluate all arguments to the function call
    // and store in sequential args registers.
    args = args.PopLeft();
    VisitArguments(expr->arguments(), &args);
    receiver_arg_count = implicit_undefined_receiver ? 0 : 1;
    CHECK_EQ(receiver_arg_count + expr->arguments()->length(),
             args.register_count());
  }

  // Resolve callee for a potential direct eval call. This block will mutate the
  // callee value.
  if (expr->is_possibly_eval() && expr->arguments()->length() > 0) {
    RegisterAllocationScope inner_register_scope(this);
    RegisterList runtime_call_args = register_allocator()->NewRegisterList(6);
    // Set up arguments for ResolvePossiblyDirectEval by copying callee, source
    // strings and function closure, and loading language and
    // position.

    // Move the first arg.
    if (spread_position == Call::kHasNonFinalSpread) {
      int feedback_slot_index =
          feedback_index(feedback_spec()->AddKeyedLoadICSlot());
      Register args_array = args[2];
      builder()
          ->LoadLiteral(Smi::FromInt(0))
          .LoadKeyedProperty(args_array, feedback_slot_index)
          .StoreAccumulatorInRegister(runtime_call_args[1]);
    } else {
      // FIXME(v8:5690): Support final spreads for eval.
      DCHECK_GE(receiver_arg_count, 0);
      builder()->MoveRegister(args[receiver_arg_count], runtime_call_args[1]);
    }
    builder()
        ->MoveRegister(callee, runtime_call_args[0])
        .MoveRegister(Register::function_closure(), runtime_call_args[2])
        .LoadLiteral(Smi::FromEnum(language_mode()))
        .StoreAccumulatorInRegister(runtime_call_args[3])
        .LoadLiteral(Smi::FromInt(expr->eval_scope_info_index()))
        .StoreAccumulatorInRegister(runtime_call_args[4])
        .LoadLiteral(Smi::FromInt(expr->position()))
        .StoreAccumulatorInRegister(runtime_call_args[5]);

    // Call ResolvePossiblyDirectEval and modify the callee.
    builder()
        ->CallRuntime(Runtime::kResolvePossiblyDirectEval, runtime_call_args)
        .StoreAccumulatorInRegister(callee);
  }

  builder()->SetExpressionPosition(expr);

  if (spread_position == Call::kHasFinalSpread) {
    DCHECK(!implicit_undefined_receiver);
    builder()->CallWithSpread(callee, args,
                              feedback_index(feedback_spec()->AddCallICSlot()));
  } else if (spread_position == Call::kHasNonFinalSpread) {
    builder()->CallJSRuntime(Context::REFLECT_APPLY_INDEX, args);
  } else if (call_type == Call::NAMED_PROPERTY_CALL ||
             call_type == Call::KEYED_PROPERTY_CALL) {
    DCHECK(!implicit_undefined_receiver);
    builder()->CallProperty(callee, args,
                            feedback_index(feedback_spec()->AddCallICSlot()));
  } else if (implicit_undefined_receiver) {
    builder()->CallUndefinedReceiver(
        callee, args, feedback_index(feedback_spec()->AddCallICSlot()));
  } else {
    builder()->CallAnyReceiver(
        callee, args, feedback_index(feedback_spec()->AddCallICSlot()));
  }
}

void BytecodeGenerator::VisitCallSuper(Call* expr) {
  RegisterAllocationScope register_scope(this);
  SuperCallReference* super = expr->expression()->AsSuperCallReference();
  const ZonePtrList<Expression>* args = expr->arguments();

  // We compile the super call differently depending on the presence of spreads
  // and their positions.
  //
  // If there is only one spread and it is the final argument, there is a
  // special ConstructWithSpread bytecode.
  //
  // It there is a non-final spread, we rewrite something like
  //    super(1, ...x, 2)
  // to
  //    %reflect_construct(constructor, [1, ...x, 2], new_target)
  //
  // That is, we implement (non-last-arg) spreads in super calls via our
  // mechanism for spreads in array literals.
  const Call::SpreadPosition spread_position = expr->spread_position();

  // Prepare the constructor to the super call.
  Register this_function = VisitForRegisterValue(super->this_function_var());
  // This register will initially hold the constructor, then afterward it will
  // hold the instance -- the lifetimes of the two don't need to overlap, and
  // this way FindNonDefaultConstructorOrConstruct can choose to write either
  // the instance or the constructor into the same register.
  Register constructor_then_instance = register_allocator()->NewRegister();

  BytecodeLabel super_ctor_call_done;

  if (spread_position == Call::kHasNonFinalSpread) {
    RegisterAllocationScope register_scope(this);
    RegisterList construct_args(constructor_then_instance);
    const Register& constructor = constructor_then_instance;

    // Generate the array containing all arguments.
    BuildCreateArrayLiteral(args, nullptr);
    Register args_array =
        register_allocator()->GrowRegisterList(&construct_args);
    builder()->StoreAccumulatorInRegister(args_array);

    Register new_target =
        register_allocator()->GrowRegisterList(&construct_args);
    VisitForRegisterValue(super->new_target_var(), new_target);

    BuildGetAndCheckSuperConstructor(this_function, new_target, constructor,
                                     &super_ctor_call_done);

    // Now pass that array to %reflect_construct.
    builder()->CallJSRuntime(Context::REFLECT_CONSTRUCT_INDEX, construct_args);
  } else {
    RegisterAllocationScope register_scope(this);
    RegisterList args_regs = register_allocator()->NewGrowableRegisterList();
    VisitArguments(args, &args_regs);

    // The new target is loaded into the new_target register from the
    // {new.target} variable.
    Register new_target = register_allocator()->NewRegister();
    VisitForRegisterValue(super->new_target_var(), new_target);

    const Register& constructor = constructor_then_instance;
    BuildGetAndCheckSuperConstructor(this_function, new_target, constructor,
                                     &super_ctor_call_done);

    builder()->LoadAccumulatorWithRegister(new_target);
    builder()->SetExpressionPosition(expr);

    int feedback_slot_index = feedback_index(feedback_spec()->AddCallICSlot());

    if (spread_position == Call::kHasFinalSpread) {
      builder()->ConstructWithSpread(constructor, args_regs,
                                     feedback_slot_index);
    } else {
      DCHECK_EQ(spread_position, Call::kNoSpread);
      // Call construct.
      // TODO(turbofan): For now we do gather feedback on super constructor
      // calls, utilizing the existing machinery to inline the actual call
      // target and the JSCreate for the implicit receiver allocation. This
      // is not an ideal solution for super constructor calls, but it gets
      // the job done for now. In the long run we might want to revisit this
      // and come up with a better way.
      builder()->Construct(constructor, args_regs, feedback_slot_index);
    }
  }

  // From here onwards, constructor_then_instance will hold the instance.
  const Register& instance = constructor_then_instance;
  builder()->StoreAccumulatorInRegister(instance);
  builder()->Bind(&super_ctor_call_done);

  BuildInstanceInitializationAfterSuperCall(this_function, instance);
  builder()->LoadAccumulatorWithRegister(instance);
}

void BytecodeGenerator::BuildInstanceInitializationAfterSuperCall(
    Register this_function, Register
```