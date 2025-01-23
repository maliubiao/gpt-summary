Response:
My goal is to analyze the provided C++ code snippet from V8's `bytecode-generator.cc` and fulfill the user's request. Here's a breakdown of my thought process:

1. **Understand the Core Request:** The user wants to know the functionality of this specific part of the `bytecode-generator.cc` file. They also want connections to JavaScript functionality, code logic examples, common programming errors, and a summary of the functionality. The "Part 5 of 11" is important context, suggesting this is part of a larger file, and the user is expecting a focused summary on *this* section.

2. **Initial Code Scan:** I'll quickly read through the function names and keywords to get a high-level idea of what's happening. I see things related to:
    * `ClassLiteral`, `BuildClassProperty`, `VisitClassLiteral`:  Looks like handling class declarations.
    * `AutoAccessorGetterBody`, `AutoAccessorSetterBody`: Generation of code for auto-generated getter/setter methods.
    * `BuildInvalidPropertyAccess`: Handling errors related to property access.
    * `BuildPrivateBrandInitialization`: Dealing with private class fields.
    * `BuildInstanceMemberInitialization`: Setting up instance properties in classes.
    * `NativeFunctionLiteral`: Handling native JavaScript functions.
    * `ConditionalChain`, `Conditional`:  Compiling conditional expressions.
    * `Literal`, `RegExpLiteral`:  Handling literal values and regular expressions.
    * `ObjectLiteral`: Processing object literal declarations.
    * `BuildFillArrayWithIterator`, `BuildCreateArrayLiteral`: Handling array literal creation, potentially with iterators (spread syntax).

3. **Identify Key Functional Areas:** Based on the initial scan, I can group the functionality into these key areas:
    * **Class Compilation:**  Handling the compilation of JavaScript classes, including properties, methods (auto-accessors), and private fields.
    * **Conditional Logic:** Compiling `if/else` and conditional chaining (`a?.b?.c`).
    * **Literal Handling:** Processing various JavaScript literal types (numbers, strings, booleans, `null`, `undefined`, regular expressions).
    * **Object Literal Compilation:** Generating bytecode for object literal declarations, including computed properties and spread syntax.
    * **Array Literal Compilation:** Generating bytecode for array literal declarations, including spread syntax and potentially iterators.

4. **Connect to JavaScript:**  For each functional area, I'll think of corresponding JavaScript constructs:
    * **Classes:** `class MyClass { constructor() { this.prop = 1; } get myProp() { ... } set myProp(val) { ... } #privateField; }`
    * **Conditionals:** `if (x > 0) { ... } else { ... }`, `a?.b?.c`
    * **Literals:** `1`, `"hello"`, `true`, `null`, `undefined`, `/abc/g`
    * **Object Literals:** `{ a: 1, b: 'hello', [key]: value, ...other }`
    * **Array Literals:** `[1, 2, 'three', ...anotherArray]`

5. **Illustrate with JavaScript Examples:** For each key area, I'll create concise JavaScript code snippets that demonstrate the functionality being compiled in the C++ code.

6. **Code Logic Reasoning (Hypothetical Input/Output):** I'll pick a few representative functions and imagine simple input JavaScript code. Then, I'll describe *in general terms* what bytecode instructions the C++ code *would likely* generate. I won't try to generate actual bytecode, as that's too complex and the user isn't asking for that level of detail. The focus is on understanding the *translation process*. For example, for a simple object literal, I can say it would likely involve instructions to create an object and then store properties.

7. **Common Programming Errors:** I'll brainstorm common errors related to the JavaScript features being compiled:
    * **Classes:**  Accessing private fields incorrectly, forgetting `super()` in derived constructors.
    * **Conditionals:**  Logic errors in conditions, unexpected behavior with truthy/falsy values.
    * **Object Literals:**  Forgetting commas, using invalid keys (before ES6), issues with `__proto__`.
    * **Array Literals:**  Off-by-one errors when accessing elements, incorrect use of spread syntax.

8. **Address the `.tq` Question:** I'll directly answer the user's question about `.tq` files and Torque.

9. **Summarize the Functionality:** Based on the key functional areas identified earlier, I'll write a concise summary of what this specific part of `bytecode-generator.cc` does. I'll emphasize that it's responsible for translating higher-level JavaScript syntax into lower-level bytecode instructions. I'll also acknowledge the "Part 5 of 11" and frame the summary accordingly.

10. **Review and Refine:** Finally, I'll read through my answer to ensure it's clear, accurate, and addresses all parts of the user's request. I'll check for consistency and correct any errors or ambiguities. I'll also try to use language that is understandable to someone who might not be a V8 internals expert.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and helpful answer to the user's request. The focus is on bridging the gap between the C++ implementation and the corresponding JavaScript concepts.
好的，让我们来分析一下 `v8/src/interpreter/bytecode-generator.cc` 的这一部分代码。

**功能归纳:**

这段代码主要负责将 JavaScript 的语法结构（AST 节点）转换为 V8 解释器可以执行的字节码。具体来说，它处理了以下类型的语法结构：

* **类 (Classes):**  包括类声明 (`ClassLiteral`)、类属性（字段和方法 `BuildClassProperty`）、静态成员 (`VisitInitializeClassStaticElementsStatement`) 以及自动访问器（`VisitAutoAccessorGetterBody`, `VisitAutoAccessorSetterBody`）。
* **错误处理:** 处理无效的属性访问，生成抛出 `TypeError` 的字节码 (`BuildInvalidPropertyAccess`)。
* **私有品牌 (Private Brands):**  初始化私有字段的品牌检查 (`BuildPrivateBrandInitialization`)。
* **实例成员初始化:** 在构造函数中初始化实例成员 (`BuildInstanceMemberInitialization`)。
* **原生函数 (Native Functions):**  处理原生 JavaScript 函数字面量 (`VisitNativeFunctionLiteral`)。
* **条件表达式 (Conditional Expressions):**  包括条件链 (`ConditionalChain`) 和 `if-else` 语句 (`Conditional`)。
* **字面量 (Literals):**  处理各种字面量类型，如数字、字符串、布尔值、`null`、`undefined` 等 (`VisitLiteral`)。
* **正则表达式字面量 (RegExp Literals):** 处理正则表达式字面量 (`VisitRegExpLiteral`)。
* **对象字面量 (Object Literals):**  处理对象字面量的创建和属性赋值，包括计算属性、getter/setter 和展开运算符 (`VisitObjectLiteral`)。
* **数组字面量 (Array Literals):** 处理数组字面量的创建，包括使用迭代器（例如，展开运算符）填充数组 (`BuildCreateArrayLiteral`, `BuildFillArrayWithIterator`)。

**关于 `.tq` 文件:**

如果 `v8/src/interpreter/bytecode-generator.cc` 以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。Torque 是一种用于编写 V8 内部函数的领域特定语言，它提供了更强的类型安全性和编译时检查。  当前的 `.cc` 结尾表示它是 C++ 代码。

**与 JavaScript 功能的关系及示例:**

这段代码直接对应着多种 JavaScript 的语言特性。以下是一些示例：

1. **类 (Classes):**

   ```javascript
   class MyClass {
     constructor(value) {
       this.myProperty = value;
     }

     getMyProperty() {
       return this.myProperty;
     }

     set myProperty(newValue) {
       this._myProperty = newValue;
     }

     static staticProperty = 10;

     #privateField = 5;

     get #privateAccessor() {
       return this.#privateField;
     }

     set #privateAccessor(value) {
       this.#privateField = value;
     }
   }
   ```

   这段 JavaScript 代码中的 `class` 声明、构造函数、属性、getter/setter、静态属性和私有字段都对应着 `bytecode-generator.cc` 中的相关处理函数，如 `VisitClassLiteral`、`BuildClassProperty`、`VisitAutoAccessorGetterBody` 等。

2. **条件表达式 (Conditional Expressions):**

   ```javascript
   const x = 10;
   const result = x > 5 ? 'large' : 'small';

   const obj = { a: { b: { c: 1 } } };
   const val = obj?.a?.b?.c;
   ```

   `VisitConditional` 处理三元运算符，`VisitConditionalChain` 处理可选链操作符 `?.`。

3. **字面量 (Literals):**

   ```javascript
   const num = 123;
   const str = "hello";
   const bool = true;
   const n = null;
   const u = undefined;
   const regex = /abc/g;
   ```

   `VisitLiteral` 会为这些不同类型的字面量生成相应的字节码指令，例如 `LoadLiteral`、`LoadBoolean`、`LoadUndefined` 等。`VisitRegExpLiteral` 处理正则表达式。

4. **对象字面量 (Object Literals):**

   ```javascript
   const key = 'dynamicKey';
   const obj = {
     a: 1,
     'b': 'two',
     [key]: 3,
     get c() { return 4; },
     set d(val) { console.log('setting d', val); },
     ...anotherObject
   };
   ```

   `VisitObjectLiteral` 负责生成创建对象和设置属性的字节码，包括处理计算属性、getter/setter 和展开运算符。

5. **数组字面量 (Array Literals):**

   ```javascript
   const arr1 = [1, 2, 3];
   const arr2 = [...arr1, 4, 5];
   ```

   `BuildCreateArrayLiteral` 用于创建数组字面量的字节码，`BuildFillArrayWithIterator` 处理展开运算符。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
class MyClass {
  constructor(value) {
    this.prop = value;
  }
}

const instance = new MyClass(5);
```

**假设输入 (AST 节点):**

* 一个 `ClassLiteral` 节点，表示 `MyClass` 的定义。
* 一个 `FunctionLiteral` 节点，表示 `constructor`。
* 一个 `ExpressionStatement` 节点，表示 `this.prop = value;`。
* 一个 `CallNew` 节点，表示 `new MyClass(5)`。

**可能的输出 (字节码指令):**

1. **对于 `ClassLiteral`:**
   * 创建类构造函数。
   * 创建类的原型对象。
   * 为构造函数和原型对象定义属性（例如 `prototype`）。

2. **对于 `constructor` 中的 `this.prop = value;`:**
   * 加载 `this` (接收者)。
   * 加载 `value` (参数)。
   * 执行属性赋值操作 (`SetNamedProperty` 或类似的指令)。

3. **对于 `new MyClass(5)`:**
   * 加载类构造函数 (`MyClass`)。
   * 加载参数 `5`。
   * 调用构造函数 (`CallConstruct` 或类似的指令)。

**用户常见的编程错误:**

1. **类相关的错误:**
   * **忘记在派生类的构造函数中调用 `super()`:**  这会导致在访问 `this` 之前使用它。`BuildInstanceMemberInitialization` 的逻辑可能需要确保在调用父类构造函数之前不会初始化实例成员。
   * **不正确地访问私有字段:**  在类外部或不被允许的上下文中访问私有字段会抛出错误。`BuildPrivateBrandInitialization` 和相关的检查会确保私有字段的访问是合法的。

   ```javascript
   class Parent {
     constructor() {
       this.parentProp = 1;
     }
   }

   class Child extends Parent {
     constructor(value) {
       this.childProp = value; // 错误：应该先调用 super()
       super();
     }
   }

   const c = new Child(2); // ReferenceError: Must call super constructor in derived class ...
   ```

2. **对象字面量相关的错误:**
   * **忘记属性之间的逗号:**  这会导致语法错误。
   * **在旧版本 JavaScript 中使用保留字作为属性名:**  虽然现在大多允许，但在旧版本中可能导致错误。
   * **不理解 `__proto__` 的行为和限制。**

   ```javascript
   const obj = { a: 1 b: 2 }; // SyntaxError: Unexpected identifier 'b'
   ```

3. **数组字面量和展开运算符相关的错误:**
   * **在期望可迭代对象的地方展开非可迭代对象:**  这会导致运行时错误。

   ```javascript
   const notIterable = 123;
   const arr = [...notIterable]; // TypeError: notIterable is not iterable
   ```

**归纳其功能 (作为第 5 部分):**

作为整个字节码生成过程的第 5 部分，这段代码专注于将 JavaScript 中关于 **类、条件逻辑、字面量 (包括对象和数组字面量)** 的抽象语法树节点转换为解释器可以理解的字节码指令。  它负责处理这些关键的语言构造，并确保生成的字节码能够正确地表达这些结构的语义。 考虑到这是一个更大的过程的一部分，可以推断前面的部分可能处理了更基础的语法元素或设置了上下文，而后面的部分可能会处理更复杂的控制流、函数调用或其他高级特性。 这部分的功能是构建 JavaScript 程序的核心组件的字节码表示。

### 提示词
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/interpreter/bytecode-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
rty(initializer, args,
                      feedback_index(feedback_spec()->AddCallICSlot()));
  }
  builder()->LoadAccumulatorWithRegister(class_constructor);
}

void BytecodeGenerator::VisitClassLiteral(ClassLiteral* expr) {
  VisitClassLiteral(expr, Register::invalid_value());
}

void BytecodeGenerator::VisitClassLiteral(ClassLiteral* expr, Register name) {
  CurrentScope current_scope(this, expr->scope());
  DCHECK_NOT_NULL(expr->scope());
  if (expr->scope()->NeedsContext()) {
    // Make sure to associate the source position for the class
    // after the block context is created. Otherwise we have a mismatch
    // between the scope and the context, where we already are in a
    // block context for the class, but not yet in the class scope. Only do
    // this if the current source position is inside the class scope though.
    // For example:
    //  * `var x = class {};` will break on `class` which is inside
    //    the class scope, so we expect the BlockContext to be pushed.
    //
    //  * `new class x {};` will break on `new` which is outside the
    //    class scope, so we expect the BlockContext to not be pushed yet.
    std::optional<BytecodeSourceInfo> source_info =
        builder()->MaybePopSourcePosition(expr->scope()->start_position());
    BuildNewLocalBlockContext(expr->scope());
    ContextScope scope(this, expr->scope());
    if (source_info) builder()->PushSourcePosition(*source_info);
    BuildClassLiteral(expr, name);
  } else {
    BuildClassLiteral(expr, name);
  }
}

void BytecodeGenerator::BuildClassProperty(ClassLiteral::Property* property) {
  RegisterAllocationScope register_scope(this);
  Register key;

  // Private methods are not initialized in BuildClassProperty.
  DCHECK_IMPLIES(property->is_private(),
                 property->kind() == ClassLiteral::Property::FIELD ||
                     property->is_auto_accessor());
  builder()->SetExpressionPosition(property->key());

  bool is_literal_store =
      property->key()->IsPropertyName() && !property->is_computed_name() &&
      !property->is_private() && !property->is_auto_accessor();

  if (!is_literal_store) {
    key = register_allocator()->NewRegister();
    if (property->is_auto_accessor()) {
      Variable* var =
          property->auto_accessor_info()->accessor_storage_name_proxy()->var();
      DCHECK_NOT_NULL(var);
      BuildVariableLoad(var, HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(key);
    } else if (property->is_computed_name()) {
      DCHECK_EQ(property->kind(), ClassLiteral::Property::FIELD);
      DCHECK(!property->is_private());
      Variable* var = property->computed_name_var();
      DCHECK_NOT_NULL(var);
      // The computed name is already evaluated and stored in a variable at
      // class definition time.
      BuildVariableLoad(var, HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(key);
    } else if (property->is_private()) {
      Variable* private_name_var = property->private_name_var();
      DCHECK_NOT_NULL(private_name_var);
      BuildVariableLoad(private_name_var, HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(key);
    } else {
      VisitForRegisterValue(property->key(), key);
    }
  }

  builder()->SetExpressionAsStatementPosition(property->value());

  if (is_literal_store) {
    VisitForAccumulatorValue(property->value());
    FeedbackSlot slot = feedback_spec()->AddDefineNamedOwnICSlot();
    builder()->DefineNamedOwnProperty(
        builder()->Receiver(),
        property->key()->AsLiteral()->AsRawPropertyName(),
        feedback_index(slot));
  } else {
    DefineKeyedOwnPropertyFlags flags = DefineKeyedOwnPropertyFlag::kNoFlags;
    if (property->NeedsSetFunctionName()) {
      // Static class fields require the name property to be set on
      // the class, meaning we can't wait until the
      // DefineKeyedOwnProperty call later to set the name.
      if (property->value()->IsClassLiteral() &&
          property->value()->AsClassLiteral()->static_initializer() !=
              nullptr) {
        VisitClassLiteral(property->value()->AsClassLiteral(), key);
      } else {
        VisitForAccumulatorValue(property->value());
        flags |= DefineKeyedOwnPropertyFlag::kSetFunctionName;
      }
    } else {
      VisitForAccumulatorValue(property->value());
    }
    FeedbackSlot slot = feedback_spec()->AddDefineKeyedOwnICSlot();
    builder()->DefineKeyedOwnProperty(builder()->Receiver(), key, flags,
                                      feedback_index(slot));
  }
}

void BytecodeGenerator::VisitInitializeClassMembersStatement(
    InitializeClassMembersStatement* stmt) {
  for (int i = 0; i < stmt->fields()->length(); i++) {
    BuildClassProperty(stmt->fields()->at(i));
  }
}

void BytecodeGenerator::VisitInitializeClassStaticElementsStatement(
    InitializeClassStaticElementsStatement* stmt) {
  for (int i = 0; i < stmt->elements()->length(); i++) {
    ClassLiteral::StaticElement* element = stmt->elements()->at(i);
    switch (element->kind()) {
      case ClassLiteral::StaticElement::PROPERTY:
        BuildClassProperty(element->property());
        break;
      case ClassLiteral::StaticElement::STATIC_BLOCK:
        VisitBlock(element->static_block());
        break;
    }
  }
}

void BytecodeGenerator::VisitAutoAccessorGetterBody(
    AutoAccessorGetterBody* stmt) {
  BuildVariableLoad(stmt->name_proxy()->var(), HoleCheckMode::kElided);
  builder()->LoadKeyedProperty(
      builder()->Receiver(),
      feedback_index(feedback_spec()->AddKeyedLoadICSlot()));
  BuildReturn(stmt->position());
}

void BytecodeGenerator::VisitAutoAccessorSetterBody(
    AutoAccessorSetterBody* stmt) {
  Register key = register_allocator()->NewRegister();
  Register value = builder()->Parameter(0);
  FeedbackSlot slot = feedback_spec()->AddKeyedStoreICSlot(language_mode());
  BuildVariableLoad(stmt->name_proxy()->var(), HoleCheckMode::kElided);

  builder()
      ->StoreAccumulatorInRegister(key)
      .LoadAccumulatorWithRegister(value)
      .SetKeyedProperty(builder()->Receiver(), key, feedback_index(slot),
                        language_mode());
}

void BytecodeGenerator::BuildInvalidPropertyAccess(MessageTemplate tmpl,
                                                   Property* property) {
  RegisterAllocationScope register_scope(this);
  const AstRawString* name = property->key()->AsVariableProxy()->raw_name();
  RegisterList args = register_allocator()->NewRegisterList(2);
  builder()
      ->LoadLiteral(Smi::FromEnum(tmpl))
      .StoreAccumulatorInRegister(args[0])
      .LoadLiteral(name)
      .StoreAccumulatorInRegister(args[1])
      .CallRuntime(Runtime::kNewTypeError, args)
      .Throw();
}

void BytecodeGenerator::BuildPrivateBrandInitialization(Register receiver,
                                                        Variable* brand) {
  BuildVariableLoad(brand, HoleCheckMode::kElided);
  int depth = execution_context()->ContextChainDepth(brand->scope());
  ContextScope* class_context = execution_context()->Previous(depth);
  if (class_context) {
    Register brand_reg = register_allocator()->NewRegister();
    FeedbackSlot slot = feedback_spec()->AddDefineKeyedOwnICSlot();
    builder()
        ->StoreAccumulatorInRegister(brand_reg)
        .LoadAccumulatorWithRegister(class_context->reg())
        .DefineKeyedOwnProperty(receiver, brand_reg,
                                DefineKeyedOwnPropertyFlag::kNoFlags,
                                feedback_index(slot));
  } else {
    // We are in the slow case where super() is called from a nested
    // arrow function or an eval(), so the class scope context isn't
    // tracked in a context register in the stack, and we have to
    // walk the context chain from the runtime to find it.
    DCHECK_NE(info()->literal()->scope()->outer_scope(), brand->scope());
    RegisterList brand_args = register_allocator()->NewRegisterList(4);
    builder()
        ->StoreAccumulatorInRegister(brand_args[1])
        .MoveRegister(receiver, brand_args[0])
        .MoveRegister(execution_context()->reg(), brand_args[2])
        .LoadLiteral(Smi::FromInt(depth))
        .StoreAccumulatorInRegister(brand_args[3])
        .CallRuntime(Runtime::kAddPrivateBrand, brand_args);
  }
}

void BytecodeGenerator::BuildInstanceMemberInitialization(Register constructor,
                                                          Register instance) {
  RegisterList args = register_allocator()->NewRegisterList(1);
  Register initializer = register_allocator()->NewRegister();

  FeedbackSlot slot = feedback_spec()->AddLoadICSlot();
  BytecodeLabel done;

  builder()
      ->LoadClassFieldsInitializer(constructor, feedback_index(slot))
      // TODO(gsathya): This jump can be elided for the base
      // constructor and derived constructor. This is only required
      // when called from an arrow function.
      .JumpIfUndefined(&done)
      .StoreAccumulatorInRegister(initializer)
      .MoveRegister(instance, args[0])
      .CallProperty(initializer, args,
                    feedback_index(feedback_spec()->AddCallICSlot()))
      .Bind(&done);
}

void BytecodeGenerator::VisitNativeFunctionLiteral(
    NativeFunctionLiteral* expr) {
  size_t entry = builder()->AllocateDeferredConstantPoolEntry();
  // Native functions don't use argument adaption and so have the special
  // kDontAdaptArgumentsSentinel as their parameter count.
  int index = feedback_spec()->AddCreateClosureParameterCount(
      kDontAdaptArgumentsSentinel);
  uint8_t flags = CreateClosureFlags::Encode(false, false, false);
  builder()->CreateClosure(entry, index, flags);
  native_function_literals_.push_back(std::make_pair(expr, entry));
}

void BytecodeGenerator::VisitConditionalChain(ConditionalChain* expr) {
  ConditionalChainControlFlowBuilder conditional_builder(
      builder(), block_coverage_builder_, expr,
      expr->conditional_chain_length());

  HoleCheckElisionMergeScope merge_elider(this);
  {
    bool should_visit_else_expression = true;
    HoleCheckElisionScope elider(this);
    for (size_t i = 0; i < expr->conditional_chain_length(); ++i) {
      if (expr->condition_at(i)->ToBooleanIsTrue()) {
        // Generate then block unconditionally as always true.
        should_visit_else_expression = false;
        HoleCheckElisionMergeScope::Branch branch(merge_elider);
        conditional_builder.ThenAt(i);
        VisitForAccumulatorValue(expr->then_expression_at(i));
        break;
      } else if (expr->condition_at(i)->ToBooleanIsFalse()) {
        // Generate else block unconditionally by skipping the then block.
        HoleCheckElisionMergeScope::Branch branch(merge_elider);
        conditional_builder.ElseAt(i);
      } else {
        VisitForTest(
            expr->condition_at(i), conditional_builder.then_labels_at(i),
            conditional_builder.else_labels_at(i), TestFallthrough::kThen);
        {
          HoleCheckElisionMergeScope::Branch branch(merge_elider);
          conditional_builder.ThenAt(i);
          VisitForAccumulatorValue(expr->then_expression_at(i));
        }
        conditional_builder.JumpToEnd();
        {
          HoleCheckElisionMergeScope::Branch branch(merge_elider);
          conditional_builder.ElseAt(i);
        }
      }
    }

    if (should_visit_else_expression) {
      VisitForAccumulatorValue(expr->else_expression());
    }
  }
  merge_elider.Merge();
}

void BytecodeGenerator::VisitConditional(Conditional* expr) {
  ConditionalControlFlowBuilder conditional_builder(
      builder(), block_coverage_builder_, expr);

  if (expr->condition()->ToBooleanIsTrue()) {
    // Generate then block unconditionally as always true.
    conditional_builder.Then();
    VisitForAccumulatorValue(expr->then_expression());
  } else if (expr->condition()->ToBooleanIsFalse()) {
    // Generate else block unconditionally if it exists.
    conditional_builder.Else();
    VisitForAccumulatorValue(expr->else_expression());
  } else {
    VisitForTest(expr->condition(), conditional_builder.then_labels(),
                 conditional_builder.else_labels(), TestFallthrough::kThen);

    HoleCheckElisionMergeScope merge_elider(this);
    conditional_builder.Then();
    {
      HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
      VisitForAccumulatorValue(expr->then_expression());
    }
    conditional_builder.JumpToEnd();

    conditional_builder.Else();
    {
      HoleCheckElisionMergeScope::Branch branch_elider(merge_elider);
      VisitForAccumulatorValue(expr->else_expression());
    }

    merge_elider.Merge();
  }
}

void BytecodeGenerator::VisitLiteral(Literal* expr) {
  if (execution_result()->IsEffect()) return;
  switch (expr->type()) {
    case Literal::kSmi:
      builder()->LoadLiteral(expr->AsSmiLiteral());
      break;
    case Literal::kHeapNumber:
      builder()->LoadLiteral(expr->AsNumber());
      break;
    case Literal::kUndefined:
      builder()->LoadUndefined();
      break;
    case Literal::kBoolean:
      builder()->LoadBoolean(expr->ToBooleanIsTrue());
      execution_result()->SetResultIsBoolean();
      break;
    case Literal::kNull:
      builder()->LoadNull();
      break;
    case Literal::kTheHole:
      builder()->LoadTheHole();
      break;
    case Literal::kString:
      builder()->LoadLiteral(expr->AsRawString());
      execution_result()->SetResultIsInternalizedString();
      break;
    case Literal::kConsString:
      builder()->LoadLiteral(expr->AsConsString());
      break;
    case Literal::kBigInt:
      builder()->LoadLiteral(expr->AsBigInt());
      break;
  }
}

void BytecodeGenerator::VisitRegExpLiteral(RegExpLiteral* expr) {
  // Materialize a regular expression literal.
  builder()->CreateRegExpLiteral(
      expr->raw_pattern(), feedback_index(feedback_spec()->AddLiteralSlot()),
      expr->flags());
}

void BytecodeGenerator::BuildCreateObjectLiteral(Register literal,
                                                 uint8_t flags, size_t entry) {
  // TODO(cbruni): Directly generate runtime call for literals we cannot
  // optimize once the CreateShallowObjectLiteral stub is in sync with the TF
  // optimizations.
  int literal_index = feedback_index(feedback_spec()->AddLiteralSlot());
  builder()
      ->CreateObjectLiteral(entry, literal_index, flags)
      .StoreAccumulatorInRegister(literal);
}

void BytecodeGenerator::VisitObjectLiteral(ObjectLiteral* expr) {
  expr->builder()->InitDepthAndFlags();

  // Fast path for the empty object literal which doesn't need an
  // AllocationSite.
  if (expr->builder()->IsEmptyObjectLiteral()) {
    DCHECK(expr->builder()->IsFastCloningSupported());
    builder()->CreateEmptyObjectLiteral();
    return;
  }

  Variable* home_object = expr->home_object();
  if (home_object != nullptr) {
    DCHECK(home_object->is_used());
    DCHECK(home_object->IsContextSlot());
  }
  MultipleEntryBlockContextScope object_literal_context_scope(
      this, home_object ? home_object->scope() : nullptr);

  // Deep-copy the literal boilerplate.
  uint8_t flags = CreateObjectLiteralFlags::Encode(
      expr->builder()->ComputeFlags(),
      expr->builder()->IsFastCloningSupported());

  Register literal = register_allocator()->NewRegister();

  // Create literal object.
  int property_index = 0;
  bool clone_object_spread =
      expr->properties()->first()->kind() == ObjectLiteral::Property::SPREAD;
  if (clone_object_spread) {
    // Avoid the slow path for spreads in the following common cases:
    //   1) `let obj = { ...source }`
    //   2) `let obj = { ...source, override: 1 }`
    //   3) `let obj = { ...source, ...overrides }`
    RegisterAllocationScope register_scope(this);
    Expression* property = expr->properties()->first()->value();
    Register from_value = VisitForRegisterValue(property);
    int clone_index = feedback_index(feedback_spec()->AddCloneObjectSlot());
    builder()->CloneObject(from_value, flags, clone_index);
    builder()->StoreAccumulatorInRegister(literal);
    property_index++;
  } else {
    size_t entry;
    // If constant properties is an empty fixed array, use a cached empty fixed
    // array to ensure it's only added to the constant pool once.
    if (expr->builder()->properties_count() == 0) {
      entry = builder()->EmptyObjectBoilerplateDescriptionConstantPoolEntry();
    } else {
      entry = builder()->AllocateDeferredConstantPoolEntry();
      object_literals_.push_back(std::make_pair(expr->builder(), entry));
    }
    BuildCreateObjectLiteral(literal, flags, entry);
  }

  // Store computed values into the literal.
  AccessorTable<ObjectLiteral::Property> accessor_table(zone());
  for (; property_index < expr->properties()->length(); property_index++) {
    ObjectLiteral::Property* property = expr->properties()->at(property_index);
    if (property->is_computed_name()) break;
    if (!clone_object_spread && property->IsCompileTimeValue()) continue;

    RegisterAllocationScope inner_register_scope(this);
    Literal* key = property->key()->AsLiteral();
    switch (property->kind()) {
      case ObjectLiteral::Property::SPREAD:
        UNREACHABLE();
      case ObjectLiteral::Property::CONSTANT:
      case ObjectLiteral::Property::MATERIALIZED_LITERAL:
        DCHECK(clone_object_spread || !property->value()->IsCompileTimeValue());
        [[fallthrough]];
      case ObjectLiteral::Property::COMPUTED: {
        // It is safe to use [[Put]] here because the boilerplate already
        // contains computed properties with an uninitialized value.
        Register key_reg;
        if (key->IsStringLiteral()) {
          DCHECK(key->IsPropertyName());
        } else {
          key_reg = register_allocator()->NewRegister();
          builder()->SetExpressionPosition(property->key());
          VisitForRegisterValue(property->key(), key_reg);
        }

        object_literal_context_scope.SetEnteredIf(
            property->value()->IsConciseMethodDefinition());
        builder()->SetExpressionPosition(property->value());

        if (property->emit_store()) {
          VisitForAccumulatorValue(property->value());
          if (key->IsStringLiteral()) {
            FeedbackSlot slot = feedback_spec()->AddDefineNamedOwnICSlot();
            builder()->DefineNamedOwnProperty(literal, key->AsRawPropertyName(),
                                              feedback_index(slot));
          } else {
            FeedbackSlot slot = feedback_spec()->AddDefineKeyedOwnICSlot();
            builder()->DefineKeyedOwnProperty(
                literal, key_reg, DefineKeyedOwnPropertyFlag::kNoFlags,
                feedback_index(slot));
          }
        } else {
          VisitForEffect(property->value());
        }
        break;
      }
      case ObjectLiteral::Property::PROTOTYPE: {
        // __proto__:null is handled by CreateObjectLiteral.
        if (property->IsNullPrototype()) break;
        DCHECK(property->emit_store());
        DCHECK(!property->NeedsSetFunctionName());
        RegisterList args = register_allocator()->NewRegisterList(2);
        builder()->MoveRegister(literal, args[0]);
        object_literal_context_scope.SetEnteredIf(false);
        builder()->SetExpressionPosition(property->value());
        VisitForRegisterValue(property->value(), args[1]);
        builder()->CallRuntime(Runtime::kInternalSetPrototype, args);
        break;
      }
      case ObjectLiteral::Property::GETTER:
        if (property->emit_store()) {
          accessor_table.LookupOrInsert(key)->getter = property;
        }
        break;
      case ObjectLiteral::Property::SETTER:
        if (property->emit_store()) {
          accessor_table.LookupOrInsert(key)->setter = property;
        }
        break;
    }
  }

    // Define accessors, using only a single call to the runtime for each pair
    // of corresponding getters and setters.
    object_literal_context_scope.SetEnteredIf(true);
    for (auto accessors : accessor_table.ordered_accessors()) {
      RegisterAllocationScope inner_register_scope(this);
      RegisterList args = register_allocator()->NewRegisterList(5);
      builder()->MoveRegister(literal, args[0]);
      VisitForRegisterValue(accessors.first, args[1]);
      VisitLiteralAccessor(accessors.second->getter, args[2]);
      VisitLiteralAccessor(accessors.second->setter, args[3]);
      builder()
          ->LoadLiteral(Smi::FromInt(NONE))
          .StoreAccumulatorInRegister(args[4])
          .CallRuntime(Runtime::kDefineAccessorPropertyUnchecked, args);
    }

  // Object literals have two parts. The "static" part on the left contains no
  // computed property names, and so we can compute its map ahead of time; see
  // Runtime_CreateObjectLiteralBoilerplate. The second "dynamic" part starts
  // with the first computed property name and continues with all properties to
  // its right. All the code from above initializes the static component of the
  // object literal, and arranges for the map of the result to reflect the
  // static order in which the keys appear. For the dynamic properties, we
  // compile them into a series of "SetOwnProperty" runtime calls. This will
  // preserve insertion order.
  for (; property_index < expr->properties()->length(); property_index++) {
    ObjectLiteral::Property* property = expr->properties()->at(property_index);
    RegisterAllocationScope inner_register_scope(this);

    bool should_be_in_object_literal_scope =
        (property->value()->IsConciseMethodDefinition() ||
         property->value()->IsAccessorFunctionDefinition());

    if (property->IsPrototype()) {
      // __proto__:null is handled by CreateObjectLiteral.
      if (property->IsNullPrototype()) continue;
      DCHECK(property->emit_store());
      DCHECK(!property->NeedsSetFunctionName());
      RegisterList args = register_allocator()->NewRegisterList(2);
      builder()->MoveRegister(literal, args[0]);

      DCHECK(!should_be_in_object_literal_scope);
      object_literal_context_scope.SetEnteredIf(false);
      builder()->SetExpressionPosition(property->value());
      VisitForRegisterValue(property->value(), args[1]);
      builder()->CallRuntime(Runtime::kInternalSetPrototype, args);
      continue;
    }

    switch (property->kind()) {
      case ObjectLiteral::Property::CONSTANT:
      case ObjectLiteral::Property::COMPUTED:
      case ObjectLiteral::Property::MATERIALIZED_LITERAL: {
        // Computed property keys don't belong to the object literal scope (even
        // if they're syntactically inside it).
        if (property->is_computed_name()) {
          object_literal_context_scope.SetEnteredIf(false);
        }
        Register key = register_allocator()->NewRegister();
        BuildLoadPropertyKey(property, key);

        object_literal_context_scope.SetEnteredIf(
            should_be_in_object_literal_scope);
        builder()->SetExpressionPosition(property->value());

        DefineKeyedOwnPropertyInLiteralFlags data_property_flags =
            DefineKeyedOwnPropertyInLiteralFlag::kNoFlags;
        if (property->NeedsSetFunctionName()) {
          // Static class fields require the name property to be set on
          // the class, meaning we can't wait until the
          // DefineKeyedOwnPropertyInLiteral call later to set the name.
          if (property->value()->IsClassLiteral() &&
              property->value()->AsClassLiteral()->static_initializer() !=
                  nullptr) {
            VisitClassLiteral(property->value()->AsClassLiteral(), key);
          } else {
            data_property_flags |=
                DefineKeyedOwnPropertyInLiteralFlag::kSetFunctionName;
            VisitForAccumulatorValue(property->value());
          }
        } else {
          VisitForAccumulatorValue(property->value());
        }

        FeedbackSlot slot =
            feedback_spec()->AddDefineKeyedOwnPropertyInLiteralICSlot();
        builder()->DefineKeyedOwnPropertyInLiteral(
            literal, key, data_property_flags, feedback_index(slot));
        break;
      }
      case ObjectLiteral::Property::GETTER:
      case ObjectLiteral::Property::SETTER: {
        // Computed property keys don't belong to the object literal scope (even
        // if they're syntactically inside it).
        if (property->is_computed_name()) {
          object_literal_context_scope.SetEnteredIf(false);
        }
        RegisterList args = register_allocator()->NewRegisterList(4);
        builder()->MoveRegister(literal, args[0]);
        BuildLoadPropertyKey(property, args[1]);

        DCHECK(should_be_in_object_literal_scope);
        object_literal_context_scope.SetEnteredIf(true);
        builder()->SetExpressionPosition(property->value());
        VisitForRegisterValue(property->value(), args[2]);
        builder()
            ->LoadLiteral(Smi::FromInt(NONE))
            .StoreAccumulatorInRegister(args[3]);
        Runtime::FunctionId function_id =
            property->kind() == ObjectLiteral::Property::GETTER
                ? Runtime::kDefineGetterPropertyUnchecked
                : Runtime::kDefineSetterPropertyUnchecked;
        builder()->CallRuntime(function_id, args);
        break;
      }
      case ObjectLiteral::Property::SPREAD: {
        // TODO(olivf, chrome:1204540) This can be slower than the Babel
        // translation. Should we compile this to a copying loop in bytecode?
        RegisterList args = register_allocator()->NewRegisterList(2);
        builder()->MoveRegister(literal, args[0]);
        builder()->SetExpressionPosition(property->value());
        object_literal_context_scope.SetEnteredIf(false);
        VisitForRegisterValue(property->value(), args[1]);
        builder()->CallRuntime(Runtime::kInlineCopyDataProperties, args);
        break;
      }
      case ObjectLiteral::Property::PROTOTYPE:
        UNREACHABLE();  // Handled specially above.
    }
  }

  if (home_object != nullptr) {
    object_literal_context_scope.SetEnteredIf(true);
    builder()->LoadAccumulatorWithRegister(literal);
    BuildVariableAssignment(home_object, Token::kInit, HoleCheckMode::kElided);
  }
  // Make sure to exit the scope before materialising the value into the
  // accumulator, to prevent the context scope from clobbering it.
  object_literal_context_scope.SetEnteredIf(false);
  builder()->LoadAccumulatorWithRegister(literal);
}

// Fill an array with values from an iterator, starting at a given index. It is
// guaranteed that the loop will only terminate if the iterator is exhausted, or
// if one of iterator.next(), value.done, or value.value fail.
//
// In pseudocode:
//
// loop {
//   value = iterator.next()
//   if (value.done) break;
//   value = value.value
//   array[index++] = value
// }
void BytecodeGenerator::BuildFillArrayWithIterator(
    IteratorRecord iterator, Register array, Register index, Register value,
    FeedbackSlot next_value_slot, FeedbackSlot next_done_slot,
    FeedbackSlot index_slot, FeedbackSlot element_slot) {
  DCHECK(array.is_valid());
  DCHECK(index.is_valid());
  DCHECK(value.is_valid());

  LoopBuilder loop_builder(builder(), nullptr, nullptr, feedback_spec());
  LoopScope loop_scope(this, &loop_builder);

  // Call the iterator's .next() method. Break from the loop if the `done`
  // property is truthy, otherwise load the value from the iterator result and
  // append the argument.
  BuildIteratorNext(iterator, value);
  builder()->LoadNamedProperty(
      value, ast_string_constants()->done_string(),
      feedback_index(feedback_spec()->AddLoadICSlot()));
  loop_builder.BreakIfTrue(ToBooleanMode::kConvertToBoolean);

  loop_builder.LoopBody();
  builder()
      // value = value.value
      ->LoadNamedProperty(value, ast_string_constants()->value_string(),
                          feedback_index(next_value_slot))
      // array[index] = value
      .StoreInArrayLiteral(array, index, feedback_index(element_slot))
      // index++
      .LoadAccumulatorWithRegister(index)
      .UnaryOperation(Token::kInc, feedback_index(index_slot))
      .StoreAccumulatorInRegister(index);
  loop_builder.BindContinueTarget();
}

void BytecodeGenerator::BuildCreateArrayLiteral(
    const ZonePtrList<Expression>* elements, ArrayLiteral* expr) {
  RegisterAllocationScope register_scope(this);
  // Make this the first register allocated so that it has a chance of aliasing
  // the next register allocated after returning from this function.
  Register array = register_allocator()->NewRegister();
  Register index = register_allocator()->NewRegister();
  SharedFeedbackSlot element_slot(feedback_spec(),
                                  FeedbackSlotKind::kStoreInArrayLiteral);
  ZonePtrList<Expression>::const_iterator current = elements->begin();
  ZonePtrList<Expression>::const_iterator end = elements->end();
  bool is_empty = elements->is_empty();

  if (!is_empty && (*current)->IsSpread()) {
    // If we have a leading spread, use CreateArrayFromIterable to create
    // an array from it and then add the remaining components to that array.
    VisitForAccumulatorValue(*current);
    builder()->SetExpressionPosition((*current)->AsSpread()->expression());
    builder()->CreateArrayFromIterable().StoreAccumulatorInRegister(array);

    if (++current != end) {
      // If there are remaning elements, prepare the index register that is
      // used for adding those elements. The next index is the length of the
      // newly created array.
      auto length = ast_string_constants()->length_string();
      int length_load_slot = feedback_index(feedback_spec()->AddLoadICSlot());
      builder()
          ->LoadNamedProperty(array, length, length_load_slot)
          .StoreAccumulatorInRegister(index);
    }
  } else {
    // There are some elements before the first (if any) spread, and we can
    // use a boilerplate when creating the initial array from those elements.

    // First, allocate a constant pool entry for the boilerplate that will
    // be created during finalization, and will contain all the constant
    // elements before the first spread. This also handle the empty array case
    // and one-shot optimization.

    ArrayLiteralBoilerplateBuilder* array_literal_builder = nullptr;
    if (expr != nullptr) {
      array_literal_builder = expr->builder();
    } else {
      DCHECK(!elements->is_empty());

      // get first_spread_index
      int first_spread_index = -1;
      for (auto iter = elements->begin(); iter != elements->end(); iter++) {
        if ((*iter)->IsSpread()) {
          first_spread_index = static_cast<int>(iter - elements->begin());
          break;
        }
      }

      array_literal_builder = zone()->New<ArrayLiteralBoilerplateBuilder>(
          elements, first_spread_index);
      array_literal_builder->InitDepthAndFlags();
    }

    DCHECK(array_literal_builder != nullptr);
    uint8_t flags = CreateArrayLiteralFlags::Encode(
        array_literal_builder->IsFastCloningSupported(),
        array_literal_builder->ComputeFlags());
    if (is_empty) {
      // Empty array literal fast-path.
      int literal_index = feedback_index(feedback_spec()->AddLiteralSlot());
      DCHECK(array_literal_builder->IsFastCloningSupported());
      builder()->CreateEmptyArrayLiteral(literal_index);
    } else {
      // Create array literal from boilerplate.
      size_t entry = builder()->AllocateDeferredConstantPoolEntry();
      array_literals_.push_back(std::make_pair(array_literal_builder, entry));
      int literal_index = feedback_index(feedback_spec()->AddLiteralSlot());
      builder()->CreateArrayLiteral(entry, literal_index, flags);
    }
    builder()->StoreAccumulatorInRegister(array);

    ZonePtrList<Expression>::const_iterator first_spread_or_end =
        array_literal_builder->first_spread_index() >= 0
            ? current + array_literal_builder->first_spread_index()
            : end;

    // Insert the missing non-constant elements, up until the first spread
    // index, into the initial array (the remaining elements will be inserted
    // below).
    DCHECK_EQ(current, elements->begin());
    int array_index = 0;
    for (; current != first_spread_or_end; ++current, array_index++) {
      Expression* subexpr = *current;
      DCHECK(!subexpr->IsSpread());
      // Skip the constants.
      if (subexpr->IsCompileTimeValue()) continue;

      builder()
          ->LoadLiteral(Smi::FromInt(array_index))
          .StoreAccumulatorInRegister(index);
      VisitForAccumulatorValue(subexpr);
      builder()->StoreInArrayLiteral(array, index,
                                     feedback_index(element_slot.Get()));
    }

    if (current != end) {
      // If there are remaining elements, prepare the index register
      // to store the nex
```