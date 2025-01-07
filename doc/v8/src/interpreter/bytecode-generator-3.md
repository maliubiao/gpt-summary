Response: The user wants a summary of the C++ code in `v8/src/interpreter/bytecode-generator.cc`.
This is part 4 of 6, suggesting a larger file handling bytecode generation for the V8 JavaScript engine.

**Breakdown of the provided code snippet:**

* **Destructuring Assignments:** The code deals heavily with destructuring assignments, both for arrays and objects. It explains how these complex assignments are translated into simpler bytecode instructions.
* **Iterator Handling:**  Array destructuring involves iterators. The code demonstrates how to get an iterator, loop through its values, and handle potential exceptions during iteration.
* **Property Access:** Object destructuring involves accessing properties of the assigned value. The code shows how to load named and keyed properties.
* **Default Values:** The code explains how default values in destructuring assignments are handled.
* **Spread Syntax:** The code demonstrates how the spread syntax (`...`) is implemented in both array and object destructuring.
* **Assignment Operators:** The code handles various assignment operators, including simple assignments and compound assignments.
* **Yield and Yield\*:** The code includes logic for the `yield` and `yield*` keywords in generator functions, covering how to suspend and resume execution.
* **Await:** The code handles the `await` keyword in asynchronous functions.
* **Property Loads:** The code explains how different kinds of property loads (named, keyed, super, private) are translated into bytecode.
* **Private Members:** There is specific code for handling private class members (methods, getters, setters).
* **Function Calls:** The code shows how regular function calls and `super()` calls are handled, including cases with spread syntax.

**High-level Goal:**  Summarize the functionality of this part of the bytecode generator. Focus on what JavaScript features are being translated into bytecode.这是 `v8/src/interpreter/bytecode-generator.cc` 源代码文件的第 4 部分，主要负责将 JavaScript 中的**赋值操作**和**控制流相关的语句 (如 yield, await, throw)** 转换为字节码指令。

**功能归纳：**

1. **处理各种类型的赋值操作：**
   - **简单赋值 ( `=` )：**  包括对变量、对象属性、数组元素的赋值。
   - **解构赋值：**  将数组或对象解构赋值给变量，包含默认值和剩余元素（spread）的处理。
   - **复合赋值 ( `+=`, `-=`, `*=`, 等 )：**  先读取左侧的值，然后执行二元运算，最后赋值。
   - **超级属性赋值 ( `super.prop = value`, `super[key] = value` )。**
   - **私有属性赋值 ( `#privateProp = value` )。**

2. **处理 Generator 函数的 `yield` 和 `yield*` 表达式：**
   - **`yield`：** 将当前 Generator 函数的执行暂停，并返回一个 IteratorResult 对象。当 Generator 函数恢复执行时，会接收一个传入的值。
   - **`yield*`：** 将迭代操作委托给另一个可迭代对象。

3. **处理 Async 函数的 `await` 表达式：**
   - **`await`：** 将 Async 函数的执行暂停，直到等待的 Promise 对象变为 resolved 状态。

4. **处理 `throw` 语句：**
   - 将抛出异常的语句转换为对应的字节码指令。

5. **处理属性访问：**
   - **属性读取：** 包括读取普通属性、计算属性、超级属性和私有属性。
   - **可选链式调用 ( `?.` )：**  处理属性访问和函数调用中可能出现的 `null` 或 `undefined` 值。

6. **处理函数调用：**
   - **普通函数调用。**
   - **`super()` 调用。**
   - **处理 `arguments` 对象。**
   - **处理 spread 语法在函数调用中的应用。**
   - **处理 `eval` 函数调用。**

**与 JavaScript 功能的关系及示例：**

这部分代码直接对应了 JavaScript 中用于修改变量值和控制程序执行流程的关键语法结构。

**JavaScript 示例：**

```javascript
// 赋值操作
let a = 10;
const obj = { x: 1, y: 2 };
obj.x = 5;
const arr = [1, 2, 3];
arr[0] = 0;

// 解构赋值
let { p, q } = obj;
let [first, ...rest] = arr;
let { z = 0 } = {}; // 默认值

// 复合赋值
a += 5;

// Generator 函数和 yield
function* myGenerator() {
  yield 1;
  let value = yield 2;
  return value;
}

const gen = myGenerator();
console.log(gen.next()); // { value: 1, done: false }
console.log(gen.next(10)); // { value: 2, done: false }
console.log(gen.next(20)); // { value: 20, done: true }

// Async 函数和 await
async function fetchData() {
  console.log("Fetching data...");
  const response = await fetch('https://example.com/data');
  const data = await response.json();
  console.log("Data received:", data);
  return data;
}

// throw 语句
function divide(a, b) {
  if (b === 0) {
    throw new Error("Cannot divide by zero!");
  }
  return a / b;
}

// 属性访问
console.log(obj.x);
console.log(obj['y']);

class MyClass {
  constructor() {
    this.#privateField = 42;
  }
  getPrivateField() {
    return this.#privateField;
  }
  #privateField;
}
const instance = new MyClass();
console.log(instance.getPrivateField());

// 函数调用
function add(x, y) {
  return x + y;
}
console.log(add(2, 3));

function logArgs(...args) {
  console.log(args);
}
logArgs(1, 2, 3);

function evil(str) {
  eval(str);
}
evil("console.log('Hello from eval!')");

class Parent {
  constructor(value) {
    this.value = value;
  }
}

class Child extends Parent {
  constructor(value) {
    super(value); // super() 调用
  }
}

// 可选链
const nestedObj = { a: { b: { c: 1 } } };
console.log(nestedObj?.a?.b?.c); // 1
console.log(nestedObj?.a?.d?.c); // undefined
```

**总结:**  第 4 部分的 `bytecode-generator.cc` 代码负责将 JavaScript 中用于修改数据、控制异步操作、处理异常以及进行属性访问和函数调用的核心语法结构翻译成 V8 虚拟机可以执行的低级指令，是 JavaScript 代码执行的关键环节。

Prompt: 
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""

    Assignment* default_init = (*target)->AsAssignment();
    DCHECK_EQ(default_init->op(), Token::kAssign);
    default_value = default_init->value();
    *target = default_init->target();
    DCHECK((*target)->IsValidReferenceExpression() || (*target)->IsPattern());
  }
  return default_value;
}

// Convert a destructuring assignment to an array literal into a sequence of
// iterator accesses into the value being assigned (in the accumulator).
//
// [a().x, ...b] = accumulator
//
//   becomes
//
// iterator = %GetIterator(accumulator)
// try {
//
//   // Individual assignments read off the value from iterator.next() This gets
//   // repeated per destructuring element.
//   if (!done) {
//     // Make sure we are considered 'done' if .next(), .done or .value fail.
//     done = true
//     var next_result = iterator.next()
//     var tmp_done = next_result.done
//     if (!tmp_done) {
//       value = next_result.value
//       done = false
//     }
//   }
//   if (done)
//     value = undefined
//   a().x = value
//
//   // A spread receives the remaining items in the iterator.
//   var array = []
//   var index = 0
//   %FillArrayWithIterator(iterator, array, index, done)
//   done = true
//   b = array
//
// } catch(e) {
//   iteration_continuation = RETHROW
// } finally {
//   %FinalizeIteration(iterator, done, iteration_continuation)
// }
void BytecodeGenerator::BuildDestructuringArrayAssignment(
    ArrayLiteral* pattern, Token::Value op,
    LookupHoistingMode lookup_hoisting_mode) {
  RegisterAllocationScope scope(this);

  Register value = register_allocator()->NewRegister();
  builder()->StoreAccumulatorInRegister(value);

  // Store the iterator in a dedicated register so that it can be closed on
  // exit, and the 'done' value in a dedicated register so that it can be
  // changed and accessed independently of the iteration result.
  IteratorRecord iterator = BuildGetIteratorRecord(IteratorType::kNormal);
  Register done = register_allocator()->NewRegister();
  builder()->LoadFalse();
  builder()->StoreAccumulatorInRegister(done);

  BuildTryFinally(
      // Try block.
      [&]() {
        Register next_result = register_allocator()->NewRegister();
        FeedbackSlot next_value_load_slot = feedback_spec()->AddLoadICSlot();
        FeedbackSlot next_done_load_slot = feedback_spec()->AddLoadICSlot();

        Spread* spread = nullptr;
        for (Expression* target : *pattern->values()) {
          if (target->IsSpread()) {
            spread = target->AsSpread();
            break;
          }

          Expression* default_value = GetDestructuringDefaultValue(&target);
          builder()->SetExpressionPosition(target);

          AssignmentLhsData lhs_data = PrepareAssignmentLhs(target);

          // if (!done) {
          //   // Make sure we are considered done if .next(), .done or .value
          //   // fail.
          //   done = true
          //   var next_result = iterator.next()
          //   var tmp_done = next_result.done
          //   if (!tmp_done) {
          //     value = next_result.value
          //     done = false
          //   }
          // }
          // if (done)
          //   value = undefined
          BytecodeLabels is_done(zone());

          builder()->LoadAccumulatorWithRegister(done);
          builder()->JumpIfTrue(ToBooleanMode::kConvertToBoolean,
                                is_done.New());

          builder()->LoadTrue().StoreAccumulatorInRegister(done);
          BuildIteratorNext(iterator, next_result);
          builder()
              ->LoadNamedProperty(next_result,
                                  ast_string_constants()->done_string(),
                                  feedback_index(next_done_load_slot))
              .JumpIfTrue(ToBooleanMode::kConvertToBoolean, is_done.New());

          // Only do the assignment if this is not a hole (i.e. 'elided').
          if (!target->IsTheHoleLiteral()) {
            builder()
                ->LoadNamedProperty(next_result,
                                    ast_string_constants()->value_string(),
                                    feedback_index(next_value_load_slot))
                .StoreAccumulatorInRegister(next_result)
                .LoadFalse()
                .StoreAccumulatorInRegister(done)
                .LoadAccumulatorWithRegister(next_result);

            // [<pattern> = <init>] = <value>
            //   becomes (roughly)
            // temp = <value>.next();
            // <pattern> = temp === undefined ? <init> : temp;
            BytecodeLabel do_assignment;
            if (default_value) {
              builder()->JumpIfNotUndefined(&do_assignment);
              // Since done == true => temp == undefined, jump directly to using
              // the default value for that case.
              is_done.Bind(builder());
              VisitInHoleCheckElisionScopeForAccumulatorValue(default_value);
            } else {
              builder()->Jump(&do_assignment);
              is_done.Bind(builder());
              builder()->LoadUndefined();
            }
            builder()->Bind(&do_assignment);

            BuildAssignment(lhs_data, op, lookup_hoisting_mode);
          } else {
            builder()->LoadFalse().StoreAccumulatorInRegister(done);
            DCHECK_EQ(lhs_data.assign_type(), NON_PROPERTY);
            is_done.Bind(builder());
          }
        }

        if (spread) {
          RegisterAllocationScope scope(this);
          BytecodeLabel is_done;

          // A spread is turned into a loop over the remainer of the iterator.
          Expression* target = spread->expression();
          builder()->SetExpressionPosition(spread);

          AssignmentLhsData lhs_data = PrepareAssignmentLhs(target);

          // var array = [];
          Register array = register_allocator()->NewRegister();
          builder()->CreateEmptyArrayLiteral(
              feedback_index(feedback_spec()->AddLiteralSlot()));
          builder()->StoreAccumulatorInRegister(array);

          // If done, jump to assigning empty array
          builder()->LoadAccumulatorWithRegister(done);
          builder()->JumpIfTrue(ToBooleanMode::kConvertToBoolean, &is_done);

          // var index = 0;
          Register index = register_allocator()->NewRegister();
          builder()->LoadLiteral(Smi::zero());
          builder()->StoreAccumulatorInRegister(index);

          // Set done to true, since it's guaranteed to be true by the time the
          // array fill completes.
          builder()->LoadTrue().StoreAccumulatorInRegister(done);

          // Fill the array with the iterator.
          FeedbackSlot element_slot =
              feedback_spec()->AddStoreInArrayLiteralICSlot();
          FeedbackSlot index_slot = feedback_spec()->AddBinaryOpICSlot();
          BuildFillArrayWithIterator(iterator, array, index, next_result,
                                     next_value_load_slot, next_done_load_slot,
                                     index_slot, element_slot);

          builder()->Bind(&is_done);
          // Assign the array to the LHS.
          builder()->LoadAccumulatorWithRegister(array);
          BuildAssignment(lhs_data, op, lookup_hoisting_mode);
        }
      },
      // Finally block.
      [&](Register iteration_continuation_token,
          Register iteration_continuation_result) {
        // Finish the iteration in the finally block.
        BuildFinalizeIteration(iterator, done, iteration_continuation_token);
      },
      HandlerTable::UNCAUGHT);

  if (!execution_result()->IsEffect()) {
    builder()->LoadAccumulatorWithRegister(value);
  }
}

// Convert a destructuring assignment to an object literal into a sequence of
// property accesses into the value being assigned (in the accumulator).
//
// { y, [x++]: a(), ...b.c } = value
//
//   becomes
//
// var rest_runtime_callargs = new Array(3);
// rest_runtime_callargs[0] = value;
//
// rest_runtime_callargs[1] = "y";
// y = value.y;
//
// var temp1 = %ToName(x++);
// rest_runtime_callargs[2] = temp1;
// a() = value[temp1];
//
// b.c =
// %CopyDataPropertiesWithExcludedPropertiesOnStack.call(rest_runtime_callargs);
void BytecodeGenerator::BuildDestructuringObjectAssignment(
    ObjectLiteral* pattern, Token::Value op,
    LookupHoistingMode lookup_hoisting_mode) {
  RegisterAllocationScope register_scope(this);

  // Store the assignment value in a register.
  Register value;
  RegisterList rest_runtime_callargs;
  if (pattern->builder()->has_rest_property()) {
    rest_runtime_callargs =
        register_allocator()->NewRegisterList(pattern->properties()->length());
    value = rest_runtime_callargs[0];
  } else {
    value = register_allocator()->NewRegister();
  }
  builder()->StoreAccumulatorInRegister(value);

  // if (value === null || value === undefined)
  //   throw new TypeError(kNonCoercible);
  //
  // Since the first property access on null/undefined will also trigger a
  // TypeError, we can elide this check. The exception is when there are no
  // properties and no rest property (this is an empty literal), or when the
  // first property is a computed name and accessing it can have side effects.
  //
  // TODO(leszeks): Also eliminate this check if the value is known to be
  // non-null (e.g. an object literal).
  if (pattern->properties()->is_empty() ||
      (pattern->properties()->at(0)->is_computed_name() &&
       pattern->properties()->at(0)->kind() != ObjectLiteralProperty::SPREAD)) {
    BytecodeLabel is_null_or_undefined, not_null_or_undefined;
    builder()
        ->JumpIfUndefinedOrNull(&is_null_or_undefined)
        .Jump(&not_null_or_undefined);

    {
      builder()->Bind(&is_null_or_undefined);
      builder()->SetExpressionPosition(pattern);
      builder()->CallRuntime(Runtime::kThrowPatternAssignmentNonCoercible,
                             value);
    }
    builder()->Bind(&not_null_or_undefined);
  }

  int i = 0;
  for (ObjectLiteralProperty* pattern_property : *pattern->properties()) {
    RegisterAllocationScope inner_register_scope(this);

    // The key of the pattern becomes the key into the RHS value, and the value
    // of the pattern becomes the target of the assignment.
    //
    // e.g. { a: b } = o becomes b = o.a
    Expression* pattern_key = pattern_property->key();
    Expression* target = pattern_property->value();
    Expression* default_value = GetDestructuringDefaultValue(&target);
    builder()->SetExpressionPosition(target);

    // Calculate this property's key into the assignment RHS value, additionally
    // storing the key for rest_runtime_callargs if needed.
    //
    // The RHS is accessed using the key either by LoadNamedProperty (if
    // value_name is valid) or by LoadKeyedProperty (otherwise).
    const AstRawString* value_name = nullptr;
    Register value_key;

    if (pattern_property->kind() != ObjectLiteralProperty::Kind::SPREAD) {
      if (pattern_key->IsPropertyName()) {
        value_name = pattern_key->AsLiteral()->AsRawPropertyName();
      }
      if (pattern->builder()->has_rest_property() || !value_name) {
        if (pattern->builder()->has_rest_property()) {
          value_key = rest_runtime_callargs[i + 1];
        } else {
          value_key = register_allocator()->NewRegister();
        }
        if (pattern_property->is_computed_name()) {
          // { [a()]: b().x } = c
          // becomes
          // var tmp = a()
          // b().x = c[tmp]
          DCHECK(!pattern_key->IsPropertyName() ||
                 !pattern_key->IsNumberLiteral());
          VisitForAccumulatorValue(pattern_key);
          builder()->ToName().StoreAccumulatorInRegister(value_key);
        } else {
          // We only need the key for non-computed properties when it is numeric
          // or is being saved for the rest_runtime_callargs.
          DCHECK(pattern_key->IsNumberLiteral() ||
                 (pattern->builder()->has_rest_property() &&
                  pattern_key->IsPropertyName()));
          VisitForRegisterValue(pattern_key, value_key);
        }
      }
    }

    AssignmentLhsData lhs_data = PrepareAssignmentLhs(target);

    // Get the value from the RHS.
    if (pattern_property->kind() == ObjectLiteralProperty::Kind::SPREAD) {
      DCHECK_EQ(i, pattern->properties()->length() - 1);
      DCHECK(!value_key.is_valid());
      DCHECK_NULL(value_name);
      builder()->CallRuntime(
          Runtime::kInlineCopyDataPropertiesWithExcludedPropertiesOnStack,
          rest_runtime_callargs);
    } else if (value_name) {
      builder()->LoadNamedProperty(
          value, value_name, feedback_index(feedback_spec()->AddLoadICSlot()));
    } else {
      DCHECK(value_key.is_valid());
      builder()->LoadAccumulatorWithRegister(value_key).LoadKeyedProperty(
          value, feedback_index(feedback_spec()->AddKeyedLoadICSlot()));
    }

    // {<pattern> = <init>} = <value>
    //   becomes
    // temp = <value>;
    // <pattern> = temp === undefined ? <init> : temp;
    if (default_value) {
      BytecodeLabel value_not_undefined;
      builder()->JumpIfNotUndefined(&value_not_undefined);
      VisitInHoleCheckElisionScopeForAccumulatorValue(default_value);
      builder()->Bind(&value_not_undefined);
    }

    BuildAssignment(lhs_data, op, lookup_hoisting_mode);

    i++;
  }

  if (!execution_result()->IsEffect()) {
    builder()->LoadAccumulatorWithRegister(value);
  }
}

void BytecodeGenerator::BuildAssignment(
    const AssignmentLhsData& lhs_data, Token::Value op,
    LookupHoistingMode lookup_hoisting_mode) {
  // Assign the value to the LHS.
  switch (lhs_data.assign_type()) {
    case NON_PROPERTY: {
      if (ObjectLiteral* pattern_as_object =
              lhs_data.expr()->AsObjectLiteral()) {
        // Split object literals into destructuring.
        BuildDestructuringObjectAssignment(pattern_as_object, op,
                                           lookup_hoisting_mode);
      } else if (ArrayLiteral* pattern_as_array =
                     lhs_data.expr()->AsArrayLiteral()) {
        // Split object literals into destructuring.
        BuildDestructuringArrayAssignment(pattern_as_array, op,
                                          lookup_hoisting_mode);
      } else {
        DCHECK(lhs_data.expr()->IsVariableProxy());
        VariableProxy* proxy = lhs_data.expr()->AsVariableProxy();
        BuildVariableAssignment(proxy->var(), op, proxy->hole_check_mode(),
                                lookup_hoisting_mode);
      }
      break;
    }
    case NAMED_PROPERTY: {
      BuildSetNamedProperty(lhs_data.object_expr(), lhs_data.object(),
                            lhs_data.name());
      break;
    }
    case KEYED_PROPERTY: {
      FeedbackSlot slot = feedback_spec()->AddKeyedStoreICSlot(language_mode());
      Register value;
      if (!execution_result()->IsEffect()) {
        value = register_allocator()->NewRegister();
        builder()->StoreAccumulatorInRegister(value);
      }
      builder()->SetKeyedProperty(lhs_data.object(), lhs_data.key(),
                                  feedback_index(slot), language_mode());
      if (!execution_result()->IsEffect()) {
        builder()->LoadAccumulatorWithRegister(value);
      }
      break;
    }
    case NAMED_SUPER_PROPERTY: {
      builder()
          ->StoreAccumulatorInRegister(lhs_data.super_property_args()[3])
          .CallRuntime(Runtime::kStoreToSuper, lhs_data.super_property_args());
      break;
    }
    case KEYED_SUPER_PROPERTY: {
      builder()
          ->StoreAccumulatorInRegister(lhs_data.super_property_args()[3])
          .CallRuntime(Runtime::kStoreKeyedToSuper,
                       lhs_data.super_property_args());
      break;
    }
    case PRIVATE_METHOD: {
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateBrandCheck(property, lhs_data.object());
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateMethodWrite,
                                 lhs_data.expr()->AsProperty());
      break;
    }
    case PRIVATE_GETTER_ONLY: {
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateBrandCheck(property, lhs_data.object());
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateSetterAccess,
                                 lhs_data.expr()->AsProperty());
      break;
    }
    case PRIVATE_SETTER_ONLY:
    case PRIVATE_GETTER_AND_SETTER: {
      Register value = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(value);
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateBrandCheck(property, lhs_data.object());
      BuildPrivateSetterAccess(lhs_data.object(), lhs_data.key(), value);
      if (!execution_result()->IsEffect()) {
        builder()->LoadAccumulatorWithRegister(value);
      }
      break;
    }
    case PRIVATE_DEBUG_DYNAMIC: {
      Register value = register_allocator()->NewRegister();
      builder()->StoreAccumulatorInRegister(value);
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateDebugDynamicSet(property, lhs_data.object(), value);
      if (!execution_result()->IsEffect()) {
        builder()->LoadAccumulatorWithRegister(value);
      }
      break;
    }
  }
}

void BytecodeGenerator::VisitAssignment(Assignment* expr) {
  AssignmentLhsData lhs_data = PrepareAssignmentLhs(expr->target());

  VisitForAccumulatorValue(expr->value());

  builder()->SetExpressionPosition(expr);
  BuildAssignment(lhs_data, expr->op(), expr->lookup_hoisting_mode());
}

void BytecodeGenerator::VisitCompoundAssignment(CompoundAssignment* expr) {
  AssignmentLhsData lhs_data = PrepareAssignmentLhs(expr->target());

  // Evaluate the value and potentially handle compound assignments by loading
  // the left-hand side value and performing a binary operation.
  switch (lhs_data.assign_type()) {
    case NON_PROPERTY: {
      VariableProxy* proxy = expr->target()->AsVariableProxy();
      BuildVariableLoad(proxy->var(), proxy->hole_check_mode());
      break;
    }
    case NAMED_PROPERTY: {
      BuildLoadNamedProperty(lhs_data.object_expr(), lhs_data.object(),
                             lhs_data.name());
      break;
    }
    case KEYED_PROPERTY: {
      FeedbackSlot slot = feedback_spec()->AddKeyedLoadICSlot();
      builder()->LoadAccumulatorWithRegister(lhs_data.key());
      BuildLoadKeyedProperty(lhs_data.object(), slot);
      break;
    }
    case NAMED_SUPER_PROPERTY: {
      builder()->CallRuntime(Runtime::kLoadFromSuper,
                             lhs_data.super_property_args().Truncate(3));
      break;
    }
    case KEYED_SUPER_PROPERTY: {
      builder()->CallRuntime(Runtime::kLoadKeyedFromSuper,
                             lhs_data.super_property_args().Truncate(3));
      break;
    }
    // BuildAssignment() will throw an error about the private method being
    // read-only.
    case PRIVATE_METHOD: {
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateBrandCheck(property, lhs_data.object());
      builder()->LoadAccumulatorWithRegister(lhs_data.key());
      break;
    }
    // For read-only properties, BuildAssignment() will throw an error about
    // the missing setter.
    case PRIVATE_GETTER_ONLY:
    case PRIVATE_GETTER_AND_SETTER: {
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateBrandCheck(property, lhs_data.object());
      BuildPrivateGetterAccess(lhs_data.object(), lhs_data.key());
      break;
    }
    case PRIVATE_SETTER_ONLY: {
      // The property access is invalid, but if the brand check fails too, we
      // need to return the error from the brand check.
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateBrandCheck(property, lhs_data.object());
      BuildInvalidPropertyAccess(MessageTemplate::kInvalidPrivateGetterAccess,
                                 lhs_data.expr()->AsProperty());
      break;
    }
    case PRIVATE_DEBUG_DYNAMIC: {
      Property* property = lhs_data.expr()->AsProperty();
      BuildPrivateDebugDynamicGet(property, lhs_data.object());
      break;
    }
  }

  BinaryOperation* binop = expr->binary_operation();
  FeedbackSlot slot = feedback_spec()->AddBinaryOpICSlot();
  BytecodeLabel short_circuit;
  if (binop->op() == Token::kNullish) {
    BytecodeLabel nullish;
    builder()
        ->JumpIfUndefinedOrNull(&nullish)
        .Jump(&short_circuit)
        .Bind(&nullish);
    VisitInHoleCheckElisionScopeForAccumulatorValue(expr->value());
  } else if (binop->op() == Token::kOr) {
    builder()->JumpIfTrue(ToBooleanMode::kConvertToBoolean, &short_circuit);
    VisitInHoleCheckElisionScopeForAccumulatorValue(expr->value());
  } else if (binop->op() == Token::kAnd) {
    builder()->JumpIfFalse(ToBooleanMode::kConvertToBoolean, &short_circuit);
    VisitInHoleCheckElisionScopeForAccumulatorValue(expr->value());
  } else if (expr->value()->IsSmiLiteral()) {
    builder()->BinaryOperationSmiLiteral(
        binop->op(), expr->value()->AsLiteral()->AsSmiLiteral(),
        feedback_index(slot));
  } else {
    Register old_value = register_allocator()->NewRegister();
    builder()->StoreAccumulatorInRegister(old_value);
    VisitForAccumulatorValue(expr->value());
    builder()->BinaryOperation(binop->op(), old_value, feedback_index(slot));
  }
  builder()->SetExpressionPosition(expr);

  BuildAssignment(lhs_data, expr->op(), expr->lookup_hoisting_mode());
  builder()->Bind(&short_circuit);
}

// Suspends the generator to resume at the next suspend_id, with output stored
// in the accumulator. When the generator is resumed, the sent value is loaded
// in the accumulator.
void BytecodeGenerator::BuildSuspendPoint(int position) {
  // Because we eliminate jump targets in dead code, we also eliminate resumes
  // when the suspend is not emitted because otherwise the below call to Bind
  // would start a new basic block and the code would be considered alive.
  if (builder()->RemainderOfBlockIsDead()) {
    return;
  }
  const int suspend_id = suspend_count_++;

  RegisterList registers = register_allocator()->AllLiveRegisters();

  // Save context, registers, and state. This bytecode then returns the value
  // in the accumulator.
  builder()->SetExpressionPosition(position);
  builder()->SuspendGenerator(generator_object(), registers, suspend_id);

  // Upon resume, we continue here.
  builder()->Bind(generator_jump_table_, suspend_id);

  // Clobbers all registers and sets the accumulator to the
  // [[input_or_debug_pos]] slot of the generator object.
  builder()->ResumeGenerator(generator_object(), registers);
}

void BytecodeGenerator::VisitYield(Yield* expr) {
  builder()->SetExpressionPosition(expr);
  VisitForAccumulatorValue(expr->expression());

  bool is_async = IsAsyncGeneratorFunction(function_kind());
  // If this is not the first yield
  if (suspend_count_ > 0) {
    if (is_async) {
      // AsyncGenerator yields (with the exception of the initial yield)
      // delegate work to the AsyncGeneratorYieldWithAwait stub, which Awaits
      // the operand and on success, wraps the value in an IteratorResult.
      //
      // In the spec the Await is a separate operation, but they are combined
      // here to reduce bytecode size.
      RegisterAllocationScope register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->MoveRegister(generator_object(), args[0])  // generator
          .StoreAccumulatorInRegister(args[1])         // value
          .CallRuntime(Runtime::kInlineAsyncGeneratorYieldWithAwait, args);
    } else {
      // Generator yields (with the exception of the initial yield) wrap the
      // value into IteratorResult.
      RegisterAllocationScope register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()
          ->StoreAccumulatorInRegister(args[0])  // value
          .LoadFalse()
          .StoreAccumulatorInRegister(args[1])  // done
          .CallRuntime(Runtime::kInlineCreateIterResultObject, args);
    }
  }

  BuildSuspendPoint(expr->position());
  // At this point, the generator has been resumed, with the received value in
  // the accumulator.

  // TODO(caitp): remove once yield* desugaring for async generators is handled
  // in BytecodeGenerator.
  if (expr->on_abrupt_resume() == Yield::kNoControl) {
    DCHECK(is_async);
    return;
  }

  Register input = register_allocator()->NewRegister();
  builder()->StoreAccumulatorInRegister(input).CallRuntime(
      Runtime::kInlineGeneratorGetResumeMode, generator_object());

  // Now dispatch on resume mode.
  static_assert(JSGeneratorObject::kNext + 1 == JSGeneratorObject::kReturn);
  static_assert(JSGeneratorObject::kReturn + 1 == JSGeneratorObject::kThrow);
  BytecodeJumpTable* jump_table =
      builder()->AllocateJumpTable(is_async ? 3 : 2, JSGeneratorObject::kNext);

  builder()->SwitchOnSmiNoFeedback(jump_table);

  if (is_async) {
    // Resume with rethrow (switch fallthrough).
    // This case is only necessary in async generators.
    builder()->SetExpressionPosition(expr);
    builder()->LoadAccumulatorWithRegister(input);
    builder()->ReThrow();

    // Add label for kThrow (next case).
    builder()->Bind(jump_table, JSGeneratorObject::kThrow);
  }

  {
    // Resume with throw (switch fallthrough in sync case).
    // TODO(leszeks): Add a debug-only check that the accumulator is
    // JSGeneratorObject::kThrow.
    builder()->SetExpressionPosition(expr);
    builder()->LoadAccumulatorWithRegister(input);
    builder()->Throw();
  }

  {
    // Resume with return.
    builder()->Bind(jump_table, JSGeneratorObject::kReturn);
    builder()->LoadAccumulatorWithRegister(input);
    if (is_async) {
      execution_control()->AsyncReturnAccumulator(kNoSourcePosition);
    } else {
      execution_control()->ReturnAccumulator(kNoSourcePosition);
    }
  }

  {
    // Resume with next.
    builder()->Bind(jump_table, JSGeneratorObject::kNext);
    BuildIncrementBlockCoverageCounterIfEnabled(expr,
                                                SourceRangeKind::kContinuation);
    builder()->LoadAccumulatorWithRegister(input);
  }
}

// Desugaring of (yield* iterable)
//
//   do {
//     const kNext = 0;
//     const kReturn = 1;
//     const kThrow = 2;
//
//     let output; // uninitialized
//
//     let iteratorRecord = GetIterator(iterable);
//     let iterator = iteratorRecord.[[Iterator]];
//     let next = iteratorRecord.[[NextMethod]];
//     let input = undefined;
//     let resumeMode = kNext;
//
//     while (true) {
//       // From the generator to the iterator:
//       // Forward input according to resumeMode and obtain output.
//       switch (resumeMode) {
//         case kNext:
//           output = next.[[Call]](iterator, « »);;
//           break;
//         case kReturn:
//           let iteratorReturn = iterator.return;
//           if (IS_NULL_OR_UNDEFINED(iteratorReturn)) {
//             if (IS_ASYNC_GENERATOR) input = await input;
//             return input;
//           }
//           output = iteratorReturn.[[Call]](iterator, «input»);
//           break;
//         case kThrow:
//           let iteratorThrow = iterator.throw;
//           if (IS_NULL_OR_UNDEFINED(iteratorThrow)) {
//             let iteratorReturn = iterator.return;
//             if (!IS_NULL_OR_UNDEFINED(iteratorReturn)) {
//               output = iteratorReturn.[[Call]](iterator, « »);
//               if (IS_ASYNC_GENERATOR) output = await output;
//               if (!IS_RECEIVER(output)) %ThrowIterResultNotAnObject(output);
//             }
//             throw MakeTypeError(kThrowMethodMissing);
//           }
//           output = iteratorThrow.[[Call]](iterator, «input»);
//           break;
//       }
//
//       if (IS_ASYNC_GENERATOR) output = await output;
//       if (!IS_RECEIVER(output)) %ThrowIterResultNotAnObject(output);
//       if (output.done) break;
//
//       // From the generator to its user:
//       // Forward output, receive new input, and determine resume mode.
//       if (IS_ASYNC_GENERATOR) {
//         // Resolve the promise for the current AsyncGeneratorRequest.
//         %_AsyncGeneratorResolve(output.value, /* done = */ false)
//       }
//       input = Suspend(output);
//       resumeMode = %GeneratorGetResumeMode();
//     }
//
//     if (resumeMode === kReturn) {
//       return output.value;
//     }
//     output.value
//   }
void BytecodeGenerator::VisitYieldStar(YieldStar* expr) {
  Register output = register_allocator()->NewRegister();
  Register resume_mode = register_allocator()->NewRegister();
  IteratorType iterator_type = IsAsyncGeneratorFunction(function_kind())
                                   ? IteratorType::kAsync
                                   : IteratorType::kNormal;

  {
    RegisterAllocationScope register_scope(this);
    RegisterList iterator_and_input = register_allocator()->NewRegisterList(2);
    VisitForAccumulatorValue(expr->expression());
    IteratorRecord iterator = BuildGetIteratorRecord(
        register_allocator()->NewRegister() /* next method */,
        iterator_and_input[0], iterator_type);

    Register input = iterator_and_input[1];
    builder()->LoadUndefined().StoreAccumulatorInRegister(input);
    builder()
        ->LoadLiteral(Smi::FromInt(JSGeneratorObject::kNext))
        .StoreAccumulatorInRegister(resume_mode);

    {
      // This loop builder does not construct counters as the loop is not
      // visible to the user, and we therefore neither pass the block coverage
      // builder nor the expression.
      //
      // In addition to the normal suspend for yield*, a yield* in an async
      // generator has 2 additional suspends:
      //   - One for awaiting the iterator result of closing the generator when
      //     resumed with a "throw" completion, and a throw method is not
      //     present on the delegated iterator
      //   - One for awaiting the iterator result yielded by the delegated
      //     iterator

      LoopBuilder loop_builder(builder(), nullptr, nullptr, feedback_spec());
      LoopScope loop_scope(this, &loop_builder);

      {
        BytecodeLabels after_switch(zone());
        BytecodeJumpTable* switch_jump_table =
            builder()->AllocateJumpTable(2, 1);

        builder()
            ->LoadAccumulatorWithRegister(resume_mode)
            .SwitchOnSmiNoFeedback(switch_jump_table);

        // Fallthrough to default case.
        // TODO(ignition): Add debug code to check that {resume_mode} really is
        // {JSGeneratorObject::kNext} in this case.
        static_assert(JSGeneratorObject::kNext == 0);
        {
          FeedbackSlot slot = feedback_spec()->AddCallICSlot();
          builder()->CallProperty(iterator.next(), iterator_and_input,
                                  feedback_index(slot));
          builder()->Jump(after_switch.New());
        }

        static_assert(JSGeneratorObject::kReturn == 1);
        builder()->Bind(switch_jump_table, JSGeneratorObject::kReturn);
        {
          const AstRawString* return_string =
              ast_string_constants()->return_string();
          BytecodeLabels no_return_method(zone());

          BuildCallIteratorMethod(iterator.object(), return_string,
                                  iterator_and_input, after_switch.New(),
                                  &no_return_method);
          no_return_method.Bind(builder());
          builder()->LoadAccumulatorWithRegister(input);
          if (iterator_type == IteratorType::kAsync) {
            // Await input.
            BuildAwait(expr->position());
            execution_control()->AsyncReturnAccumulator(kNoSourcePosition);
          } else {
            execution_control()->ReturnAccumulator(kNoSourcePosition);
          }
        }

        static_assert(JSGeneratorObject::kThrow == 2);
        builder()->Bind(switch_jump_table, JSGeneratorObject::kThrow);
        {
          const AstRawString* throw_string =
              ast_string_constants()->throw_string();
          BytecodeLabels no_throw_method(zone());
          BuildCallIteratorMethod(iterator.object(), throw_string,
                                  iterator_and_input, after_switch.New(),
                                  &no_throw_method);

          // If there is no "throw" method, perform IteratorClose, and finally
          // throw a TypeError.
          no_throw_method.Bind(builder());
          BuildIteratorClose(iterator, expr);
          builder()->CallRuntime(Runtime::kThrowThrowMethodMissing);
        }

        after_switch.Bind(builder());
      }

      if (iterator_type == IteratorType::kAsync) {
        // Await the result of the method invocation.
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
"""


```