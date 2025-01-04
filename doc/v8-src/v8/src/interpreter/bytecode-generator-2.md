Response: The user wants a summary of the C++ code in `v8/src/interpreter/bytecode-generator.cc`, specifically part 3 of 6. The summary should focus on the functionality implemented in this section and its relation to JavaScript features, providing JavaScript examples where applicable.

Let's break down the code section by section:

*   **Class Literal Handling (VisitClassLiteral, BuildClassLiteral, BuildClassProperty, VisitInitializeClassMembersStatement, VisitInitializeClassStaticElementsStatement):**  This clearly deals with the compilation of `class` syntax in JavaScript.
*   **Auto Accessor Handling (VisitAutoAccessorGetterBody, VisitAutoAccessorSetterBody):**  This relates to the implementation of getter and setter methods within classes, especially auto accessors.
*   **Private Brand Initialization (BuildPrivateBrandInitialization):** This seems to handle the initialization of private class members, likely related to the `#` syntax.
*   **Instance Member Initialization (BuildInstanceMemberInitialization):**  Focuses on initializing instance properties of classes.
*   **Native Function Literals (VisitNativeFunctionLiteral):** Deals with the compilation of built-in or "native" JavaScript functions.
*   **Conditional Expressions (VisitConditionalChain, VisitConditional):**  Covers the compilation of `if`, `else if`, and `else` statements, including optional chaining.
*   **Literal Values (VisitLiteral):**  Handles the compilation of basic JavaScript literal values like numbers, strings, booleans, `null`, and `undefined`.
*   **Regular Expression Literals (VisitRegExpLiteral):**  Compiles regular expression literals (`/.../`).
*   **Object Literals (BuildCreateObjectLiteral, VisitObjectLiteral, VisitLiteralAccessor, BuildLoadPropertyKey):**  A significant portion dedicated to compiling object literals (`{}`). This includes handling computed property names, getters, setters, and the `__proto__` property.
*   **Array Literals (BuildFillArrayWithIterator, BuildCreateArrayLiteral, VisitArrayLiteral):** Handles the compilation of array literals (`[]`), including spread syntax.
*   **Variable Handling (VisitVariableProxy, IsVariableInRegister, SetVariableInRegister, GetPotentialVariableInAccumulator, BuildVariableLoad, BuildVariableLoadForAccumulatorValue):**  Focuses on loading values from variables, considering different variable locations (local, global, context, etc.) and handling temporal dead zones (TDZ).
*   **Return Statements (BuildReturn, BuildAsyncReturn):**  Compiles `return` statements, handling both synchronous and asynchronous functions.
*   **Exception Handling (BuildReThrow, RememberHoleCheckInCurrentBlock, BuildThrowIfHole, VariableNeedsHoleCheckInCurrentBlock, VariableNeedsHoleCheckInCurrentBlockForAssignment, BuildHoleCheckForVariableAssignment):**  Deals with throwing and re-throwing exceptions, particularly related to uninitialized variables (TDZ).
*   **Variable Assignment (BuildVariableAssignment):**  Compiles variable assignments, considering different variable locations and modes (e.g., `let`, `const`).
*   **Property Access (BuildLoadNamedProperty, BuildSetNamedProperty, BuildStoreGlobal, BuildLoadKeyedProperty):**  Covers accessing and setting properties using both named and computed keys.
*   **Assignment Left-Hand Side Preparation (AssignmentLhsData, PrepareAssignmentLhs):**  Prepares the left-hand side of assignment expressions to determine the target of the assignment.
*   **Iteration Finalization (BuildFinalizeIteration):**  Handles the cleanup process when exiting loops (e.g., calling the `return` method of an iterator).
*   **Destructuring Default Values (GetDestructuringDefaultValue):** Extracts the default value from destructuring assignments.

Based on this analysis, the main function of this code section appears to be the *generation of bytecode* for various JavaScript expressions and statements related to classes, object and array literals, variable access and assignment, control flow (conditionals), and iteration cleanup. It also handles error conditions related to uninitialized variables (TDZ).
This section of the `bytecode-generator.cc` file in V8 focuses on generating bytecode for several key JavaScript language features. Specifically, it handles:

**1. Class Syntax:**

*   **Class Declarations and Expressions:** It compiles `class` declarations and expressions, including named and anonymous classes.
*   **Class Members:**  It generates bytecode for defining class properties (fields), methods (including private ones), static members, and auto-accessors (getters/setters for fields).
*   **Class Initialization:** It handles the initialization logic for instance members and static members within a class.

**JavaScript Example:**

```javascript
class MyClass {
  constructor(value) {
    this.instanceProperty = value;
  }

  myMethod() {
    console.log("Method called");
  }

  static staticMethod() {
    console.log("Static method called");
  }

  get myAccessor() {
    return this.instanceProperty * 2;
  }

  set myAccessor(newValue) {
    this.instanceProperty = newValue / 2;
  }

  #privateField = 0;

  get #privateAccessor() {
    return this.#privateField;
  }

  static {
    console.log("Static initialization block");
  }
}
```

**2. Object and Array Literals:**

*   **Object Literal Creation:** It compiles object literals, including handling computed property names, getters, setters, and the `__proto__` property. It uses optimized bytecode instructions for common cases.
*   **Array Literal Creation:** It generates bytecode for creating array literals, including handling spread syntax (`...`).

**JavaScript Example:**

```javascript
const myObject = {
  a: 1,
  ["b" + "c"]: 2, // Computed property name
  get d() { return this.a + 1; },
  set e(value) { this.a = value; },
  __proto__: null
};

const myArray = [1, 2, ...[3, 4], 5];
```

**3. Variable Access and Assignment:**

*   **Variable Loading:** It generates bytecode to load the value of a variable, considering different variable scopes (local, global, context) and handling the Temporal Dead Zone (TDZ) for `let` and `const` declarations.
*   **Variable Assignment:** It compiles variable assignments, including assignments to different scopes and handling `const` reassignments (throwing errors).

**JavaScript Example:**

```javascript
let x = 10;
const y = 20;
console.log(x); // Variable load
x = 30;         // Variable assignment
// y = 40;      // Would cause an error due to const reassignment

function myFunction() {
  let localVariable = 5;
  console.log(localVariable);
}
```

**4. Control Flow (Conditional Expressions):**

*   **Conditional Operator (`? :`) and `if`/`else` Statements:** It generates bytecode for conditional expressions and `if`/`else` statements, including handling optional chaining (`?.`).

**JavaScript Example:**

```javascript
const age = 25;
const status = age >= 18 ? "Adult" : "Minor";

if (age >= 18) {
  console.log("You can vote.");
} else {
  console.log("You cannot vote yet.");
}

const myObj = { prop: { value: 1 } };
const val = myObj?.prop?.value; // Optional chaining
```

**5. Function Literals (Native Functions):**

*   **Native Function Literals:** It compiles references to built-in JavaScript functions.

**JavaScript Example:**

```javascript
const toStringFunc = Object.prototype.toString;
```

**6. Return Statements:**

*   **`return` Statements:** It generates bytecode for returning values from functions, including handling asynchronous functions (`async function`).

**JavaScript Example:**

```javascript
function add(a, b) {
  return a + b;
}

async function fetchData() {
  const response = await fetch('/data');
  return response.json();
}
```

**7. Error Handling (TDZ):**

*   **Temporal Dead Zone (TDZ) Checks:**  It generates bytecode to enforce the TDZ, throwing `ReferenceError` if `let` or `const` variables are accessed before their declaration.

**JavaScript Example:**

```javascript
// console.log(myVar); // Would cause a ReferenceError (TDZ)
let myVar = 10;
console.log(myVar);
```

**In summary, this part of `bytecode-generator.cc` is crucial for translating various common and fundamental JavaScript syntax constructs into efficient bytecode that can be executed by the V8 interpreter.** It handles the core mechanics of defining classes, creating objects and arrays, accessing and modifying variables, and controlling the flow of execution through conditional statements. The generated bytecode ensures the correct semantics and error handling behavior as defined by the JavaScript language specification.

Prompt: 
```
这是目录为v8/src/interpreter/bytecode-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
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
      // to store the next element, which comes from the first spread.
      builder()
          ->LoadLiteral(Smi::FromInt(array_index))
          .StoreAccumulatorInRegister(index);
    }
  }

  // Now build insertions for the remaining elements from current to end.
  SharedFeedbackSlot index_slot(feedback_spec(), FeedbackSlotKind::kBinaryOp);
  SharedFeedbackSlot length_slot(
      feedback_spec(), feedback_spec()->GetStoreICSlot(LanguageMode::kStrict));
  for (; current != end; ++current) {
    Expression* subexpr = *current;
    if (subexpr->IsSpread()) {
      RegisterAllocationScope scope(this);
      builder()->SetExpressionPosition(subexpr->AsSpread()->expression());
      VisitForAccumulatorValue(subexpr->AsSpread()->expression());
      builder()->SetExpressionPosition(subexpr->AsSpread()->expression());
      IteratorRecord iterator = BuildGetIteratorRecord(IteratorType::kNormal);

      Register value = register_allocator()->NewRegister();
      FeedbackSlot next_value_load_slot = feedback_spec()->AddLoadICSlot();
      FeedbackSlot next_done_load_slot = feedback_spec()->AddLoadICSlot();
      FeedbackSlot real_index_slot = index_slot.Get();
      FeedbackSlot real_element_slot = element_slot.Get();
      BuildFillArrayWithIterator(iterator, array, index, value,
                                 next_value_load_slot, next_done_load_slot,
                                 real_index_slot, real_element_slot);
    } else if (!subexpr->IsTheHoleLiteral()) {
      // literal[index++] = subexpr
      VisitForAccumulatorValue(subexpr);
      builder()
          ->StoreInArrayLiteral(array, index,
                                feedback_index(element_slot.Get()))
          .LoadAccumulatorWithRegister(index);
      // Only increase the index if we are not the last element.
      if (current + 1 != end) {
        builder()
            ->UnaryOperation(Token::kInc, feedback_index(index_slot.Get()))
            .StoreAccumulatorInRegister(index);
      }
    } else {
      // literal.length = ++index
      // length_slot is only used when there are holes.
      auto length = ast_string_constants()->length_string();
      builder()
          ->LoadAccumulatorWithRegister(index)
          .UnaryOperation(Token::kInc, feedback_index(index_slot.Get()))
          .StoreAccumulatorInRegister(index)
          .SetNamedProperty(array, length, feedback_index(length_slot.Get()),
                            LanguageMode::kStrict);
    }
  }

  builder()->LoadAccumulatorWithRegister(array);
}

void BytecodeGenerator::VisitArrayLiteral(ArrayLiteral* expr) {
  expr->builder()->InitDepthAndFlags();
  BuildCreateArrayLiteral(expr->values(), expr);
}

void BytecodeGenerator::VisitVariableProxy(VariableProxy* proxy) {
  builder()->SetExpressionPosition(proxy);
  BuildVariableLoad(proxy->var(), proxy->hole_check_mode());
}

bool BytecodeGenerator::IsVariableInRegister(Variable* var, Register reg) {
  BytecodeRegisterOptimizer* optimizer = builder()->GetRegisterOptimizer();
  if (optimizer) {
    return optimizer->IsVariableInRegister(var, reg);
  }
  return false;
}

void BytecodeGenerator::SetVariableInRegister(Variable* var, Register reg) {
  BytecodeRegisterOptimizer* optimizer = builder()->GetRegisterOptimizer();
  if (optimizer) {
    optimizer->SetVariableInRegister(var, reg);
  }
}

Variable* BytecodeGenerator::GetPotentialVariableInAccumulator() {
  BytecodeRegisterOptimizer* optimizer = builder()->GetRegisterOptimizer();
  if (optimizer) {
    return optimizer->GetPotentialVariableInAccumulator();
  }
  return nullptr;
}

void BytecodeGenerator::BuildVariableLoad(Variable* variable,
                                          HoleCheckMode hole_check_mode,
                                          TypeofMode typeof_mode) {
  switch (variable->location()) {
    case VariableLocation::LOCAL: {
      Register source(builder()->Local(variable->index()));
      // We need to load the variable into the accumulator, even when in a
      // VisitForRegisterScope, in order to avoid register aliasing if
      // subsequent expressions assign to the same variable.
      builder()->LoadAccumulatorWithRegister(source);
      if (VariableNeedsHoleCheckInCurrentBlock(variable, hole_check_mode)) {
        BuildThrowIfHole(variable);
      }
      break;
    }
    case VariableLocation::PARAMETER: {
      Register source;
      if (variable->IsReceiver()) {
        source = builder()->Receiver();
      } else {
        source = builder()->Parameter(variable->index());
      }
      // We need to load the variable into the accumulator, even when in a
      // VisitForRegisterScope, in order to avoid register aliasing if
      // subsequent expressions assign to the same variable.
      builder()->LoadAccumulatorWithRegister(source);
      if (VariableNeedsHoleCheckInCurrentBlock(variable, hole_check_mode)) {
        BuildThrowIfHole(variable);
      }
      break;
    }
    case VariableLocation::UNALLOCATED: {
      // The global identifier "undefined" is immutable. Everything
      // else could be reassigned. For performance, we do a pointer comparison
      // rather than checking if the raw_name is really "undefined".
      if (variable->raw_name() == ast_string_constants()->undefined_string()) {
        builder()->LoadUndefined();
      } else {
        FeedbackSlot slot = GetCachedLoadGlobalICSlot(typeof_mode, variable);
        builder()->LoadGlobal(variable->raw_name(), feedback_index(slot),
                              typeof_mode);
      }
      break;
    }
    case VariableLocation::CONTEXT: {
      int depth = execution_context()->ContextChainDepth(variable->scope());
      ContextScope* context = execution_context()->Previous(depth);
      Register context_reg;
      if (context) {
        context_reg = context->reg();
        depth = 0;
      } else {
        context_reg = execution_context()->reg();
      }

      BytecodeArrayBuilder::ContextSlotMutability immutable =
          (variable->maybe_assigned() == kNotAssigned)
              ? BytecodeArrayBuilder::kImmutableSlot
              : BytecodeArrayBuilder::kMutableSlot;
      Register acc = Register::virtual_accumulator();
      if (immutable == BytecodeArrayBuilder::kImmutableSlot &&
          IsVariableInRegister(variable, acc)) {
        return;
      }

      builder()->LoadContextSlot(context_reg, variable, depth, immutable);
      if (VariableNeedsHoleCheckInCurrentBlock(variable, hole_check_mode)) {
        BuildThrowIfHole(variable);
      }
      if (immutable == BytecodeArrayBuilder::kImmutableSlot) {
        SetVariableInRegister(variable, acc);
      }
      break;
    }
    case VariableLocation::LOOKUP: {
      switch (variable->mode()) {
        case VariableMode::kDynamicLocal: {
          Variable* local_variable = variable->local_if_not_shadowed();
          int depth =
              execution_context()->ContextChainDepth(local_variable->scope());
          ContextKind context_kind = (local_variable->scope()->is_script_scope()
                                          ? ContextKind::kScriptContext
                                          : ContextKind::kDefault);
          builder()->LoadLookupContextSlot(variable->raw_name(), typeof_mode,
                                           context_kind,
                                           local_variable->index(), depth);
          if (VariableNeedsHoleCheckInCurrentBlock(local_variable,
                                                   hole_check_mode)) {
            BuildThrowIfHole(local_variable);
          }
          break;
        }
        case VariableMode::kDynamicGlobal: {
          int depth =
              current_scope()->ContextChainLengthUntilOutermostSloppyEval();
          // TODO(1008414): Add back caching here when bug is fixed properly.
          FeedbackSlot slot = feedback_spec()->AddLoadGlobalICSlot(typeof_mode);

          builder()->LoadLookupGlobalSlot(variable->raw_name(), typeof_mode,
                                          feedback_index(slot), depth);
          break;
        }
        default: {
          // Normally, private names should not be looked up dynamically,
          // but we make an exception in debug-evaluate, in that case the
          // lookup will be done in %SetPrivateMember() and %GetPrivateMember()
          // calls, not here.
          DCHECK(!variable->raw_name()->IsPrivateName());
          builder()->LoadLookupSlot(variable->raw_name(), typeof_mode);
          break;
        }
      }
      break;
    }
    case VariableLocation::MODULE: {
      int depth = execution_context()->ContextChainDepth(variable->scope());
      builder()->LoadModuleVariable(variable->index(), depth);
      if (VariableNeedsHoleCheckInCurrentBlock(variable, hole_check_mode)) {
        BuildThrowIfHole(variable);
      }
      break;
    }
    case VariableLocation::REPL_GLOBAL: {
      DCHECK(variable->IsReplGlobal());
      FeedbackSlot slot = GetCachedLoadGlobalICSlot(typeof_mode, variable);
      builder()->LoadGlobal(variable->raw_name(), feedback_index(slot),
                            typeof_mode);
      break;
    }
  }
}

void BytecodeGenerator::BuildVariableLoadForAccumulatorValue(
    Variable* variable, HoleCheckMode hole_check_mode, TypeofMode typeof_mode) {
  ValueResultScope accumulator_result(this);
  BuildVariableLoad(variable, hole_check_mode, typeof_mode);
}

void BytecodeGenerator::BuildReturn(int source_position) {
  if (v8_flags.trace) {
    RegisterAllocationScope register_scope(this);
    Register result = register_allocator()->NewRegister();
    // Runtime returns {result} value, preserving accumulator.
    builder()->StoreAccumulatorInRegister(result).CallRuntime(
        Runtime::kTraceExit, result);
  }
  builder()->SetStatementPosition(source_position);
  builder()->Return();
}

void BytecodeGenerator::BuildAsyncReturn(int source_position) {
  RegisterAllocationScope register_scope(this);

  if (IsAsyncGeneratorFunction(info()->literal()->kind())) {
    RegisterList args = register_allocator()->NewRegisterList(3);
    builder()
        ->MoveRegister(generator_object(), args[0])  // generator
        .StoreAccumulatorInRegister(args[1])         // value
        .LoadTrue()
        .StoreAccumulatorInRegister(args[2])  // done
        .CallRuntime(Runtime::kInlineAsyncGeneratorResolve, args);
  } else {
    DCHECK(IsAsyncFunction(info()->literal()->kind()) ||
           IsModuleWithTopLevelAwait(info()->literal()->kind()));
    RegisterList args = register_allocator()->NewRegisterList(2);
    builder()
        ->MoveRegister(generator_object(), args[0])  // generator
        .StoreAccumulatorInRegister(args[1])         // value
        .CallRuntime(Runtime::kInlineAsyncFunctionResolve, args);
  }

  BuildReturn(source_position);
}

void BytecodeGenerator::BuildReThrow() { builder()->ReThrow(); }

void BytecodeGenerator::RememberHoleCheckInCurrentBlock(Variable* variable) {
  if (!v8_flags.ignition_elide_redundant_tdz_checks) return;

  // The first N-1 variables that need hole checks may be cached in a bitmap to
  // elide subsequent hole checks in the same basic block, where N is
  // Variable::kHoleCheckBitmapBits.
  //
  // This numbering is done during bytecode generation instead of scope analysis
  // for 2 reasons:
  //
  // 1. There may be multiple eagerly compiled inner functions during a single
  // run of scope analysis, so a global numbering will result in fewer variables
  // with cacheable hole checks.
  //
  // 2. Compiler::CollectSourcePositions reparses functions and checks that the
  // recompiled bytecode is identical. Therefore the numbering must be kept
  // identical regardless of whether a function is eagerly compiled as part of
  // an outer compilation or recompiled during source position collection. The
  // simplest way to guarantee identical numbering is to scope it to the
  // compilation instead of scope analysis.
  variable->RememberHoleCheckInBitmap(hole_check_bitmap_,
                                      vars_in_hole_check_bitmap_);
}

void BytecodeGenerator::BuildThrowIfHole(Variable* variable) {
  if (variable->is_this()) {
    DCHECK(variable->mode() == VariableMode::kConst);
    builder()->ThrowSuperNotCalledIfHole();
  } else {
    builder()->ThrowReferenceErrorIfHole(variable->raw_name());
  }
  RememberHoleCheckInCurrentBlock(variable);
}

bool BytecodeGenerator::VariableNeedsHoleCheckInCurrentBlock(
    Variable* variable, HoleCheckMode hole_check_mode) {
  return hole_check_mode == HoleCheckMode::kRequired &&
         !variable->HasRememberedHoleCheck(hole_check_bitmap_);
}

bool BytecodeGenerator::VariableNeedsHoleCheckInCurrentBlockForAssignment(
    Variable* variable, Token::Value op, HoleCheckMode hole_check_mode) {
  return VariableNeedsHoleCheckInCurrentBlock(variable, hole_check_mode) ||
         (variable->is_this() && variable->mode() == VariableMode::kConst &&
          op == Token::kInit);
}

void BytecodeGenerator::BuildHoleCheckForVariableAssignment(Variable* variable,
                                                            Token::Value op) {
  DCHECK(!IsPrivateMethodOrAccessorVariableMode(variable->mode()));
  DCHECK(VariableNeedsHoleCheckInCurrentBlockForAssignment(
      variable, op, HoleCheckMode::kRequired));
  if (variable->is_this()) {
    DCHECK(variable->mode() == VariableMode::kConst && op == Token::kInit);
    // Perform an initialization check for 'this'. 'this' variable is the
    // only variable able to trigger bind operations outside the TDZ
    // via 'super' calls.
    //
    // Do not remember the hole check because this bytecode throws if 'this' is
    // *not* the hole, i.e. the opposite of the TDZ hole check.
    builder()->ThrowSuperAlreadyCalledIfNotHole();
  } else {
    // Perform an initialization check for let/const declared variables.
    // E.g. let x = (x = 20); is not allowed.
    DCHECK(IsLexicalVariableMode(variable->mode()));
    BuildThrowIfHole(variable);
  }
}

void BytecodeGenerator::BuildVariableAssignment(
    Variable* variable, Token::Value op, HoleCheckMode hole_check_mode,
    LookupHoistingMode lookup_hoisting_mode) {
  VariableMode mode = variable->mode();
  RegisterAllocationScope assignment_register_scope(this);
  switch (variable->location()) {
    case VariableLocation::PARAMETER:
    case VariableLocation::LOCAL: {
      Register destination;
      if (VariableLocation::PARAMETER == variable->location()) {
        if (variable->IsReceiver()) {
          destination = builder()->Receiver();
        } else {
          destination = builder()->Parameter(variable->index());
        }
      } else {
        destination = builder()->Local(variable->index());
      }

      if (VariableNeedsHoleCheckInCurrentBlockForAssignment(variable, op,
                                                            hole_check_mode)) {
        // Load destination to check for hole.
        Register value_temp = register_allocator()->NewRegister();
        builder()
            ->StoreAccumulatorInRegister(value_temp)
            .LoadAccumulatorWithRegister(destination);
        BuildHoleCheckForVariableAssignment(variable, op);
        builder()->LoadAccumulatorWithRegister(value_temp);
      }

      if ((mode != VariableMode::kConst && mode != VariableMode::kUsing &&
           mode != VariableMode::kAwaitUsing) ||
          op == Token::kInit) {
        if (op == Token::kInit) {
          if (variable->HasHoleCheckUseInSameClosureScope()) {
            // After initializing a variable it won't be the hole anymore, so
            // elide subsequent checks.
            RememberHoleCheckInCurrentBlock(variable);
          }
          if (mode == VariableMode::kUsing) {
            RegisterList args = register_allocator()->NewRegisterList(2);
            builder()
                ->MoveRegister(current_disposables_stack_, args[0])
                .StoreAccumulatorInRegister(args[1])
                .CallRuntime(Runtime::kAddDisposableValue, args);
          } else if (mode == VariableMode::kAwaitUsing) {
            RegisterList args = register_allocator()->NewRegisterList(2);
            builder()
                ->MoveRegister(current_disposables_stack_, args[0])
                .StoreAccumulatorInRegister(args[1])
                .CallRuntime(Runtime::kAddAsyncDisposableValue, args);
          }
        }
        builder()->StoreAccumulatorInRegister(destination);
      } else if (variable->throw_on_const_assignment(language_mode()) &&
                 mode == VariableMode::kConst) {
        builder()->CallRuntime(Runtime::kThrowConstAssignError);
      } else if (variable->throw_on_const_assignment(language_mode()) &&
                 mode == VariableMode::kUsing) {
        builder()->CallRuntime(Runtime::kThrowUsingAssignError);
      }
      break;
    }
    case VariableLocation::UNALLOCATED: {
      BuildStoreGlobal(variable);
      break;
    }
    case VariableLocation::CONTEXT: {
      int depth = execution_context()->ContextChainDepth(variable->scope());
      ContextScope* context = execution_context()->Previous(depth);
      Register context_reg;

      if (context) {
        context_reg = context->reg();
        depth = 0;
      } else {
        context_reg = execution_context()->reg();
      }

      if (VariableNeedsHoleCheckInCurrentBlockForAssignment(variable, op,
                                                            hole_check_mode)) {
        // Load destination to check for hole.
        Register value_temp = register_allocator()->NewRegister();
        builder()
            ->StoreAccumulatorInRegister(value_temp)
            .LoadContextSlot(context_reg, variable, depth,
                             BytecodeArrayBuilder::kMutableSlot);

        BuildHoleCheckForVariableAssignment(variable, op);
        builder()->LoadAccumulatorWithRegister(value_temp);
      }

      if (mode != VariableMode::kConst || op == Token::kInit) {
        if (op == Token::kInit &&
            variable->HasHoleCheckUseInSameClosureScope()) {
          // After initializing a variable it won't be the hole anymore, so
          // elide subsequent checks.
          RememberHoleCheckInCurrentBlock(variable);
        }
        builder()->StoreContextSlot(context_reg, variable, depth);
      } else if (variable->throw_on_const_assignment(language_mode())) {
        builder()->CallRuntime(Runtime::kThrowConstAssignError);
      }
      break;
    }
    case VariableLocation::LOOKUP: {
      builder()->StoreLookupSlot(variable->raw_name(), language_mode(),
                                 lookup_hoisting_mode);
      break;
    }
    case VariableLocation::MODULE: {
      DCHECK(IsDeclaredVariableMode(mode));

      if (mode == VariableMode::kConst && op != Token::kInit) {
        builder()->CallRuntime(Runtime::kThrowConstAssignError);
        break;
      }

      // If we don't throw above, we know that we're dealing with an
      // export because imports are const and we do not generate initializing
      // assignments for them.
      DCHECK(variable->IsExport());

      int depth = execution_context()->ContextChainDepth(variable->scope());
      if (VariableNeedsHoleCheckInCurrentBlockForAssignment(variable, op,
                                                            hole_check_mode)) {
        Register value_temp = register_allocator()->NewRegister();
        builder()
            ->StoreAccumulatorInRegister(value_temp)
            .LoadModuleVariable(variable->index(), depth);
        BuildHoleCheckForVariableAssignment(variable, op);
        builder()->LoadAccumulatorWithRegister(value_temp);
      }
      builder()->StoreModuleVariable(variable->index(), depth);
      break;
    }
    case VariableLocation::REPL_GLOBAL: {
      // A let or const declaration like 'let x = 7' is effectively translated
      // to:
      //   <top of the script>:
      //     ScriptContext.x = TheHole;
      //   ...
      //   <where the actual 'let' is>:
      //     ScriptContextTable.x = 7; // no hole check
      //
      // The ScriptContext slot for 'x' that we store to here is not
      // necessarily the ScriptContext of this script, but rather the
      // first ScriptContext that has a slot for name 'x'.
      DCHECK(variable->IsReplGlobal());
      if (op == Token::kInit) {
        RegisterList store_args = register_allocator()->NewRegisterList(2);
        builder()
            ->StoreAccumulatorInRegister(store_args[1])
            .LoadLiteral(variable->raw_name())
            .StoreAccumulatorInRegister(store_args[0]);
        builder()->CallRuntime(
            Runtime::kStoreGlobalNoHoleCheckForReplLetOrConst, store_args);
      } else {
        if (mode == VariableMode::kConst) {
          builder()->CallRuntime(Runtime::kThrowConstAssignError);
        } else {
          BuildStoreGlobal(variable);
        }
      }
      break;
    }
  }
}

void BytecodeGenerator::BuildLoadNamedProperty(const Expression* object_expr,
                                               Register object,
                                               const AstRawString* name) {
  FeedbackSlot slot = GetCachedLoadICSlot(object_expr, name);
  builder()->LoadNamedProperty(object, name, feedback_index(slot));
}

void BytecodeGenerator::BuildSetNamedProperty(const Expression* object_expr,
                                              Register object,
                                              const AstRawString* name) {
  Register value;
  if (!execution_result()->IsEffect()) {
    value = register_allocator()->NewRegister();
    builder()->StoreAccumulatorInRegister(value);
  }

  FeedbackSlot slot = GetCachedStoreICSlot(object_expr, name);
  builder()->SetNamedProperty(object, name, feedback_index(slot),
                              language_mode());

  if (!execution_result()->IsEffect()) {
    builder()->LoadAccumulatorWithRegister(value);
  }
}

void BytecodeGenerator::BuildStoreGlobal(Variable* variable) {
  Register value;
  if (!execution_result()->IsEffect()) {
    value = register_allocator()->NewRegister();
    builder()->StoreAccumulatorInRegister(value);
  }

  FeedbackSlot slot = GetCachedStoreGlobalICSlot(language_mode(), variable);
  builder()->StoreGlobal(variable->raw_name(), feedback_index(slot));

  if (!execution_result()->IsEffect()) {
    builder()->LoadAccumulatorWithRegister(value);
  }
}

void BytecodeGenerator::BuildLoadKeyedProperty(Register object,
                                               FeedbackSlot slot) {
  if (v8_flags.enable_enumerated_keyed_access_bytecode &&
      current_for_in_scope() != nullptr) {
    Variable* key = GetPotentialVariableInAccumulator();
    if (key != nullptr) {
      ForInScope* scope = current_for_in_scope()->GetForInScope(key);
      if (scope != nullptr) {
        Register enum_index = scope->enum_index();
        Register cache_type = scope->cache_type();
        builder()->LoadEnumeratedKeyedProperty(object, enum_index, cache_type,
                                               feedback_index(slot));
        return;
      }
    }
  }
  builder()->LoadKeyedProperty(object, feedback_index(slot));
}

// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::NonProperty(Expression* expr) {
  return AssignmentLhsData(NON_PROPERTY, expr, RegisterList(), Register(),
                           Register(), nullptr, nullptr);
}
// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::NamedProperty(Expression* object_expr,
                                                    Register object,
                                                    const AstRawString* name) {
  return AssignmentLhsData(NAMED_PROPERTY, nullptr, RegisterList(), object,
                           Register(), object_expr, name);
}
// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::KeyedProperty(Register object,
                                                    Register key) {
  return AssignmentLhsData(KEYED_PROPERTY, nullptr, RegisterList(), object, key,
                           nullptr, nullptr);
}
// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::NamedSuperProperty(
    RegisterList super_property_args) {
  return AssignmentLhsData(NAMED_SUPER_PROPERTY, nullptr, super_property_args,
                           Register(), Register(), nullptr, nullptr);
}
// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::PrivateMethodOrAccessor(
    AssignType type, Property* property, Register object, Register key) {
  return AssignmentLhsData(type, property, RegisterList(), object, key, nullptr,
                           nullptr);
}
// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::PrivateDebugEvaluate(AssignType type,
                                                           Property* property,
                                                           Register object) {
  return AssignmentLhsData(type, property, RegisterList(), object, Register(),
                           nullptr, nullptr);
}
// static
BytecodeGenerator::AssignmentLhsData
BytecodeGenerator::AssignmentLhsData::KeyedSuperProperty(
    RegisterList super_property_args) {
  return AssignmentLhsData(KEYED_SUPER_PROPERTY, nullptr, super_property_args,
                           Register(), Register(), nullptr, nullptr);
}

BytecodeGenerator::AssignmentLhsData BytecodeGenerator::PrepareAssignmentLhs(
    Expression* lhs, AccumulatorPreservingMode accumulator_preserving_mode) {
  // Left-hand side can only be a property, a global or a variable slot.
  Property* property = lhs->AsProperty();
  AssignType assign_type = Property::GetAssignType(property);

  // Evaluate LHS expression.
  switch (assign_type) {
    case NON_PROPERTY:
      return AssignmentLhsData::NonProperty(lhs);
    case NAMED_PROPERTY: {
      AccumulatorPreservingScope scope(this, accumulator_preserving_mode);
      Register object = VisitForRegisterValue(property->obj());
      const AstRawString* name =
          property->key()->AsLiteral()->AsRawPropertyName();
      return AssignmentLhsData::NamedProperty(property->obj(), object, name);
    }
    case KEYED_PROPERTY: {
      AccumulatorPreservingScope scope(this, accumulator_preserving_mode);
      Register object = VisitForRegisterValue(property->obj());
      Register key = VisitForRegisterValue(property->key());
      return AssignmentLhsData::KeyedProperty(object, key);
    }
    case PRIVATE_METHOD:
    case PRIVATE_GETTER_ONLY:
    case PRIVATE_SETTER_ONLY:
    case PRIVATE_GETTER_AND_SETTER: {
      DCHECK(!property->IsSuperAccess());
      AccumulatorPreservingScope scope(this, accumulator_preserving_mode);
      Register object = VisitForRegisterValue(property->obj());
      Register key = VisitForRegisterValue(property->key());
      return AssignmentLhsData::PrivateMethodOrAccessor(assign_type, property,
                                                        object, key);
    }
    case PRIVATE_DEBUG_DYNAMIC: {
      AccumulatorPreservingScope scope(this, accumulator_preserving_mode);
      Register object = VisitForRegisterValue(property->obj());
      // Do not visit the key here, instead we will look them up at run time.
      return AssignmentLhsData::PrivateDebugEvaluate(assign_type, property,
                                                     object);
    }
    case NAMED_SUPER_PROPERTY: {
      AccumulatorPreservingScope scope(this, accumulator_preserving_mode);
      RegisterList super_property_args =
          register_allocator()->NewRegisterList(4);
      BuildThisVariableLoad();
      builder()->StoreAccumulatorInRegister(super_property_args[0]);
      BuildVariableLoad(
          property->obj()->AsSuperPropertyReference()->home_object()->var(),
          HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(super_property_args[1]);
      builder()
          ->LoadLiteral(property->key()->AsLiteral()->AsRawPropertyName())
          .StoreAccumulatorInRegister(super_property_args[2]);
      return AssignmentLhsData::NamedSuperProperty(super_property_args);
    }
    case KEYED_SUPER_PROPERTY: {
      AccumulatorPreservingScope scope(this, accumulator_preserving_mode);
      RegisterList super_property_args =
          register_allocator()->NewRegisterList(4);
      BuildThisVariableLoad();
      builder()->StoreAccumulatorInRegister(super_property_args[0]);
      BuildVariableLoad(
          property->obj()->AsSuperPropertyReference()->home_object()->var(),
          HoleCheckMode::kElided);
      builder()->StoreAccumulatorInRegister(super_property_args[1]);
      VisitForRegisterValue(property->key(), super_property_args[2]);
      return AssignmentLhsData::KeyedSuperProperty(super_property_args);
    }
  }
  UNREACHABLE();
}

// Build the iteration finalizer called in the finally block of an iteration
// protocol execution. This closes the iterator if needed, and suppresses any
// exception it throws if necessary, including the exception when the return
// method is not callable.
//
// In pseudo-code, this builds:
//
// if (!done) {
//   try {
//     let method = iterator.return
//     if (method !== null && method !== undefined) {
//       let return_val = method.call(iterator)
//       if (!%IsObject(return_val)) throw TypeError
//     }
//   } catch (e) {
//     if (iteration_continuation != RETHROW)
//       rethrow e
//   }
// }
//
// For async iterators, iterator.close() becomes await iterator.close().
void BytecodeGenerator::BuildFinalizeIteration(
    IteratorRecord iterator, Register done,
    Register iteration_continuation_token) {
  RegisterAllocationScope register_scope(this);
  BytecodeLabels iterator_is_done(zone());

  // if (!done) {
  builder()->LoadAccumulatorWithRegister(done).JumpIfTrue(
      ToBooleanMode::kConvertToBoolean, iterator_is_done.New());

  {
    RegisterAllocationScope inner_register_scope(this);
    BuildTryCatch(
        // try {
        //   let method = iterator.return
        //   if (method !== null && method !== undefined) {
        //     let return_val = method.call(iterator)
        //     if (!%IsObject(return_val)) throw TypeError
        //   }
        // }
        [&]() {
          Register method = register_allocator()->NewRegister();
          builder()
              ->LoadNamedProperty(
                  iterator.object(), ast_string_constants()->return_string(),
                  feedback_index(feedback_spec()->AddLoadICSlot()))
              .JumpIfUndefinedOrNull(iterator_is_done.New())
              .StoreAccumulatorInRegister(method);

          RegisterList args(iterator.object());
          builder()->CallProperty(
              method, args, feedback_index(feedback_spec()->AddCallICSlot()));
          if (iterator.type() == IteratorType::kAsync) {
            BuildAwait();
          }
          builder()->JumpIfJSReceiver(iterator_is_done.New());
          {
            // Throw this exception inside the try block so that it is
            // suppressed by the iteration continuation if necessary.
            RegisterAllocationScope register_scope(this);
            Register return_result = register_allocator()->NewRegister();
            builder()
                ->StoreAccumulatorInRegister(return_result)
                .CallRuntime(Runtime::kThrowIteratorResultNotAnObject,
                             return_result);
          }
        },

        // catch (e) {
        //   if (iteration_continuation != RETHROW)
        //     rethrow e
        // }
        [&](Register context) {
          // Reuse context register to store the exception.
          Register close_exception = context;
          builder()->StoreAccumulatorInRegister(close_exception);

          BytecodeLabel suppress_close_exception;
          builder()
              ->LoadLiteral(Smi::FromInt(
                  static_cast<int>(TryFinallyContinuationToken::kRethrowToken)))
              .CompareReference(iteration_continuation_token)
              .JumpIfTrue(ToBooleanMode::kAlreadyBoolean,
                          &suppress_close_exception)
              .LoadAccumulatorWithRegister(close_exception)
              .ReThrow()
              .Bind(&suppress_close_exception);
        },
        catch_prediction());
  }

  iterator_is_done.Bind(builder());
}

// Get the default value of a destructuring target. Will mutate the
// destructuring target expression if there is a default value.
//
// For
//   a = b
// in
//   let {a = b} = c
// returns b and mutates the input into a.
Expression* BytecodeGenerator::GetDestructuringDefaultValue(
    Expression** target) {
  Expression* default_value = nullptr;
  if ((*target)->IsAssignment()) {
"""


```