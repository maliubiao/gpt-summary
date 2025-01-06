Response: Let's break down the thought process for analyzing this Torque file.

1. **Initial Scan and Keyword Spotting:**  The first thing I'd do is quickly scan the file for keywords and structure. I see:
    * `// Copyright`:  Indicates a standard V8 file.
    * `@abstract`, `@generateBodyDescriptor`, `extern class`: These are Torque-specific annotations defining class properties and generation behavior. "abstract" suggests this is a base class.
    * `extends HeapObject`: Shows inheritance from a fundamental V8 object type.
    * `macro`:  Indicates reusable code snippets or functions within Torque.
    * `const`, `length`, `elements`:  Common data structure components.
    * `Slot`: A custom type, likely for indexing.
    * `enum ContextSlot`:  Defines a set of named constants related to context slots.
    * `builtin`:  Indicates a call to a C++ function within V8.
    * `namespace runtime`:  More C++ interaction.
    * `typeswitch`: A control flow structure, similar to a `switch` statement, but operating on types.
    * `dcheck`: A debug assertion, useful for understanding assumptions.
    * `kInitialContextSlotValue`, `kEmptyScopeInfo`, `Undefined`, `TheHole`:  Well-known V8 constants.

2. **Identifying the Core Purpose (Contexts):** The filename `contexts.tq` and the prominent use of `Context` as a base class immediately point to the file's main purpose: defining and manipulating execution contexts within V8.

3. **Understanding the `Context` Hierarchy:**  The `extern class ... extends Context` declarations show a clear hierarchy of different context types: `AwaitContext`, `BlockContext`, `CatchContext`, etc. This suggests that different kinds of code execution environments require specific context information.

4. **Analyzing `Context` Members:**
    * `GetScopeInfo()`:  This macro strongly suggests a connection to lexical scoping in JavaScript. Scope information is crucial for resolving variable names.
    * `length: Smi`:  Indicates the number of slots the context holds.
    * `elements[length]: Object`: This is the core data storage of the context, an array of `Object`s. It implies that contexts store variables and other data.

5. **Deciphering `ContextSlot`:** The `ContextSlot` enum is the key to understanding *what* is stored in the `elements` array. The names like `SCOPE_INFO_INDEX`, `PREVIOUS_INDEX`, `ARRAY_FUNCTION_INDEX`, etc., reveal the types of information associated with a context. Many of these relate directly to JavaScript built-in objects and functionalities. The `NativeContext` slots are especially interesting because they seem to hold references to fundamental JavaScript objects and maps.

6. **Examining Macros (Focus on Function Context):** The `AllocateSyntheticFunctionContext` macro demonstrates how a specific type of context, `FunctionContext`, is created. It initializes the `length`, `elements`, `SCOPE_INFO_INDEX`, and `PREVIOUS_INDEX`. This reinforces the idea that function execution has its own context.

7. **Understanding `NativeContext`:**  The existence of `NativeContext` and the numerous `ContextSlot` entries related to it suggest this is a special, global context holding essential runtime information for the JavaScript engine.

8. **Analyzing `StoreContextElementAndUpdateSideData`:** This macro introduces the concept of "side data" and its relation to `ScriptContext`. The logic inside this macro is crucial. It checks if a context variable is constant (`kContextSidePropertyConst`), tracks changes, and potentially invalidates dependent compiled code. This is directly related to V8's optimization strategies. The handling of `MutableHeapNumber` is also a detail worth noting.

9. **Connecting to JavaScript Functionality:**  Now, with a good understanding of the code, I can start linking it to JavaScript concepts. The different context types directly map to different JavaScript execution environments. The `NativeContext` holds the built-in objects. The `ScopeInfo` connects to lexical scoping. The `StoreContextElementAndUpdateSideData` is related to variable assignment and potential optimizations.

10. **Formulating JavaScript Examples:**  Based on the identified connections, I can create illustrative JavaScript examples. For instance, the different context types can be shown with block scopes (`{ let x = 1; }`), functions, `eval()`, and modules. The `NativeContext` relates to global objects like `Array`, `Object`, etc. The side data concept is harder to directly illustrate in simple JavaScript but relates to how V8 optimizes variable access.

11. **Identifying Potential Errors:** The `StoreContextElementAndUpdateSideData` macro provides insights into potential programming errors. Reassigning `const` variables, modifying variables that are assumed to be constant by the optimizer, and unexpected type changes for variables are all relevant.

12. **Developing Input/Output Scenarios:** For the code logic, especially the `StoreContextElementAndUpdateSideData` macro, I can construct hypothetical scenarios:
    * **Input:** A `ScriptContext`, an index corresponding to a variable, and a new value.
    * **Output:** The context's `elements` array updated, the side data potentially updated to reflect mutability, and potentially invalidation of dependent code. I'd consider cases where the variable is initially `const`, a `let`, and the types of values being assigned.

13. **Review and Refine:**  Finally, I'd review my analysis, ensuring that the explanations are clear, concise, and accurate. I'd check for any missing connections or areas where the explanation could be improved. For instance, making the link between `ScopeInfo` and lexical scope more explicit. Also, ensuring the JavaScript examples accurately reflect the concepts.
This Torque file (`v8/src/objects/contexts.tq`) defines the structure and manipulation of **execution contexts** within the V8 JavaScript engine. Execution contexts are fundamental to how JavaScript code is executed and how variables are accessed.

Here's a breakdown of its functionality:

**Core Functionality: Defining Execution Contexts**

* **`Context` Class:**  This is the abstract base class for all context types. It represents a scope in JavaScript execution.
    * `GetScopeInfo()`:  A macro to retrieve information about the variables and their scope within this context. This directly relates to **lexical scoping** in JavaScript.
    * `length: Smi`:  Indicates the number of "slots" or storage locations within the context.
    * `elements[length]: Object`:  This is the core of the context, an array that stores variables and other values associated with this scope.

* **Specific Context Types:**  The file defines various concrete context types that inherit from `Context`, each representing a different kind of scope in JavaScript:
    * `ScriptContext`: Represents the top-level scope of a script.
    * `FunctionContext`: Represents the scope created when a function is called.
    * `BlockContext`: Represents the scope created by a block of code (e.g., inside `if` statements, `for` loops with `let` or `const`).
    * `CatchContext`: Represents the scope of a `catch` block.
    * `EvalContext`: Represents the scope created by `eval()`.
    * `ModuleContext`: Represents the scope of an ECMAScript module.
    * `WithContext`: Represents the scope created by a `with` statement (generally discouraged).
    * `AwaitContext`: Represents the scope within an `async function` when awaiting a promise.
    * `DebugEvaluateContext`: Used for evaluating expressions during debugging.
    * `NativeContext`: A special context holding global objects and built-in functions (like `Array`, `Object`, etc.).

* **`ScriptContextTable`:** This class likely manages a collection of `ScriptContext` objects, potentially for caching or lookup purposes.

**Relationship to JavaScript Functionality (with Examples)**

The `Context` objects directly correspond to the different levels of scoping in JavaScript.

* **Global Scope (NativeContext):**  The `NativeContext` holds references to built-in JavaScript objects and functions that are available globally.
    ```javascript
    // In JavaScript, these are globally accessible because they reside in the NativeContext
    console.log(Array);
    console.log(Object);
    console.log(Math.random());
    ```

* **Function Scope (FunctionContext):** When a function is called, a `FunctionContext` is created to hold its local variables and parameters.
    ```javascript
    function myFunction(arg) {
      let localVar = 10; // localVar is stored in the FunctionContext
      console.log(arg + localVar);
    }
    myFunction(5);
    ```

* **Block Scope (BlockContext):** Introduced with `let` and `const`, block scopes create `BlockContext` objects.
    ```javascript
    if (true) {
      let blockVar = 20; // blockVar is stored in a BlockContext
      console.log(blockVar);
    }
    // console.log(blockVar); // Error: blockVar is not defined here
    ```

* **Catch Scope (CatchContext):** The `catch` block creates its own scope for the error variable.
    ```javascript
    try {
      throw new Error("Something went wrong");
    } catch (error) {
      // 'error' is in the CatchContext
      console.error(error.message);
    }
    // console.log(error); // Error: error is not defined here
    ```

* **Module Scope (ModuleContext):** Modules have their own isolated scope.
    ```javascript
    // In moduleA.js
    export const moduleVar = 30;

    // In moduleB.js
    import { moduleVar } from './moduleA.js';
    console.log(moduleVar); // Accesses the variable from moduleA's ModuleContext
    ```

**Code Logic and Reasoning (with Hypothetical Inputs and Outputs)**

The macros `AllocateSyntheticFunctionContext`, `InitContextSlot`, and `ContextSlot` are involved in creating and accessing slots within context objects. The most complex logic lies in `StoreContextElementAndUpdateSideData`.

**Scenario: Updating a variable in a `ScriptContext`**

**Hypothetical Input:**

* `c`: A `ScriptContext` object.
* `i`: An `intptr` representing the index of a variable within the `c.elements` array. Let's say this index corresponds to a top-level `let` variable named `myVar`.
* `newValue`: An `Object` representing the new value to be assigned to `myVar`.

**Assumptions:**

* The `ScriptContext` `c` has been initialized and contains a slot at index `i` for `myVar`.
* The side data mechanism for tracking mutability is enabled.

**Possible Outputs and Reasoning:**

1. **Initial Assignment (`myVar` was previously uninitialized or `TheHole`):**
   * The code will check the side data associated with this slot. If it's `Undefined`, it means it's the first assignment.
   * The side data will be updated to mark `myVar` as potentially constant initially (`kContextSidePropertyConst`).
   * `c.elements[i]` will be set to `newValue`.

2. **Reassigning a `let` variable with a different value:**
   * The code will check the side data. If it was `kContextSidePropertyConst` or `kContextSidePropertySmi` (assuming it held a primitive initially), it means the variable is being mutated.
   * The side data will be updated to reflect the new mutability status (e.g., `kContextSidePropertyOther` if the type changes or `kContextSidePropertyHeapNumber` if it becomes a `HeapNumber`).
   * If there's dependent optimized code relying on the assumption that `myVar`'s value doesn't change, that code might be invalidated (using `runtime::InvalidateDependentCodeForScriptContextSlot`).
   * `c.elements[i]` will be set to `newValue`.

3. **Reassigning a `let` variable with the same value (or same numeric value for `HeapNumber`):**
   * The code will detect that the old and new values are effectively the same.
   * No changes will be made to the side data, and dependent code won't be invalidated.

**User-Common Programming Errors**

This code directly relates to how V8 handles variable assignments and mutability, especially with `let` and `const`. Common programming errors this code helps the engine manage include:

1. **Reassigning `const` variables:** While this code doesn't directly prevent reassigning `const` (that's a parser/semantics check), the side data mechanism is crucial for optimizing access to `const` variables. If a user somehow bypasses the usual checks (e.g., through `eval` in strict mode scenarios), this code would detect the mutation and potentially invalidate optimizations.

   ```javascript
   const myConstant = 5;
   // myConstant = 10; // This would throw a TypeError in normal JavaScript

   // However, consider a scenario where internal V8 logic attempts an update
   // or a highly unusual case with 'eval' and strict mode interactions.
   ```

2. **Unexpected type changes for variables:** JavaScript is dynamically typed. If a variable is initially assigned a number and later a string, V8 needs to track this change. The `StoreContextElementAndUpdateSideData` macro handles these transitions.

   ```javascript
   let myVariable = 10; // Initially a number
   myVariable = "hello"; // Type changes to string
   ```

3. **Modifying variables that are assumed to be constant by the optimizer:** V8 aggressively optimizes code based on assumptions about variable types and values. If a `let` variable is only assigned once and never changes in practice, the optimizer might treat it as a constant. If the code later mutates this variable, V8 needs to invalidate those optimizations to maintain correctness.

   ```javascript
   let counter = 0;
   function increment() {
     counter++;
     // V8 might optimize code assuming 'counter' doesn't change within certain scopes
   }
   ```

4. **Incorrectly relying on the immutability of primitive values:** While primitive values themselves are immutable, reassigning a variable holding a primitive creates a new binding. The context mechanism manages these bindings.

   ```javascript
   let a = 5;
   let b = a;
   a = 10;
   console.log(b); // Output: 5 (b still refers to the old value)
   ```

**In summary, `v8/src/objects/contexts.tq` is a fundamental piece of V8 that defines how execution environments are structured, how variables are stored within those environments, and how the engine manages the mutability of variables, which is crucial for both correctness and performance optimizations.**

Prompt: 
```
这是目录为v8/src/objects/contexts.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

@abstract
// We normally don't generate a BodyDescriptor for an abstact class, but here we
// do since all context classes share the same BodyDescriptor.
@generateBodyDescriptor
extern class Context extends HeapObject {
  macro GetScopeInfo(): ScopeInfo {
    return *ContextSlot(this, ContextSlot::SCOPE_INFO_INDEX);
  }
  const length: Smi;
  elements[length]: Object;
}

@cppObjectLayoutDefinition
extern class ScriptContextTable extends HeapObject {
  const capacity: Smi;
  length: Smi;
  names_to_context_index: NameToIndexHashTable;
  objects[capacity]: Context;
}

extern class AwaitContext extends Context generates 'TNode<Context>';
extern class BlockContext extends Context generates 'TNode<Context>';
extern class CatchContext extends Context generates 'TNode<Context>';
extern class DebugEvaluateContext extends Context
    generates 'TNode<Context>';
extern class EvalContext extends Context generates 'TNode<Context>';
extern class ModuleContext extends Context generates 'TNode<Context>';
extern class ScriptContext extends Context generates 'TNode<Context>';
extern class WithContext extends Context generates 'TNode<Context>';

extern class FunctionContext extends Context generates 'TNode<Context>';

const kInitialContextSlotValue: Smi = 0;

@export
macro AllocateSyntheticFunctionContext(
    nativeContext: NativeContext, slots: constexpr int31): FunctionContext {
  return AllocateSyntheticFunctionContext(
      nativeContext, Convert<intptr>(slots));
}

macro AllocateSyntheticFunctionContext(
    nativeContext: NativeContext, slots: intptr): FunctionContext {
  static_assert(slots >= ContextSlot::MIN_CONTEXT_SLOTS);
  const map =
      *ContextSlot(nativeContext, ContextSlot::FUNCTION_CONTEXT_MAP_INDEX);
  const result = new FunctionContext{
    map,
    length: Convert<Smi>(slots),
    elements: ...ConstantIterator<Smi>(kInitialContextSlotValue)
  };
  InitContextSlot(result, ContextSlot::SCOPE_INFO_INDEX, kEmptyScopeInfo);
  InitContextSlot(result, ContextSlot::PREVIOUS_INDEX, Undefined);
  return result;
}

extern class NativeContext extends Context;

type Slot<Container : type extends Context, T : type extends Object> extends
    intptr;

// We cannot use ContextSlot() for initialization since that one asserts the
// slot has the right type already.
macro InitContextSlot<
    ArgumentContext: type, AnnotatedContext: type, T: type, U: type>(
    context: ArgumentContext, index: Slot<AnnotatedContext, T>,
    value: U): void {
  // Make sure the arguments have the right type.
  const context: AnnotatedContext = context;
  const value: T = value;
  dcheck(TaggedEqual(context.elements[index], kInitialContextSlotValue));
  context.elements[index] = value;
}

macro ContextSlot<ArgumentContext: type, AnnotatedContext: type, T: type>(
    context: ArgumentContext, index: Slot<AnnotatedContext, T>):&T {
  const context: AnnotatedContext = context;
  return torque_internal::unsafe::ReferenceCast<T>(&context.elements[index]);
}

macro NativeContextSlot<T: type>(
    context: NativeContext, index: Slot<NativeContext, T>):&T {
  return ContextSlot(context, index);
}
macro NativeContextSlot<T: type>(
    context: Context, index: Slot<NativeContext, T>):&T {
  return ContextSlot(LoadNativeContext(context), index);
}
macro NativeContextSlot<C: type, T: type>(
    implicit context: C)(index: Slot<NativeContext, T>):&T {
  return NativeContextSlot(context, index);
}

extern enum ContextSlot extends intptr constexpr 'Context::Field' {
  SCOPE_INFO_INDEX: Slot<Context, ScopeInfo>,
  // Zero is used for the NativeContext, Undefined is used for synthetic
  // function contexts.
  PREVIOUS_INDEX: Slot<Context, Context|Zero|Undefined>,

  AGGREGATE_ERROR_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  ARRAY_BUFFER_FUN_INDEX: Slot<NativeContext, Constructor>,
  ARRAY_BUFFER_NOINIT_FUN_INDEX: Slot<NativeContext, JSFunction>,
  ARRAY_BUFFER_MAP_INDEX: Slot<NativeContext, Map>,
  ARRAY_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  ARRAY_JOIN_STACK_INDEX: Slot<NativeContext, Undefined|FixedArray>,
  OBJECT_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  ITERATOR_RESULT_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_MAP_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_FILTER_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_TAKE_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_DROP_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_FLAT_MAP_HELPER_MAP_INDEX: Slot<NativeContext, Map>,
  ITERATOR_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  VALID_ITERATOR_WRAPPER_MAP_INDEX: Slot<NativeContext, Map>,
  JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  JS_MAP_MAP_INDEX: Slot<NativeContext, Map>,
  JS_SET_MAP_INDEX: Slot<NativeContext, Map>,
  MATH_RANDOM_CACHE_INDEX: Slot<NativeContext, FixedDoubleArray>,
  MATH_RANDOM_INDEX_INDEX: Slot<NativeContext, Smi>,
  NUMBER_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  PROXY_REVOCABLE_RESULT_MAP_INDEX: Slot<NativeContext, Map>,
  REFLECT_APPLY_INDEX: Slot<NativeContext, Callable>,
  REGEXP_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  REGEXP_LAST_MATCH_INFO_INDEX: Slot<NativeContext, RegExpMatchInfo>,
  INITIAL_STRING_ITERATOR_MAP_INDEX: Slot<NativeContext, Map>,
  INITIAL_ARRAY_ITERATOR_MAP_INDEX: Slot<NativeContext, Map>,
  INITIAL_ITERATOR_PROTOTYPE_INDEX: Slot<NativeContext, JSObject>,
  SLOW_OBJECT_WITH_NULL_PROTOTYPE_MAP: Slot<NativeContext, Map>,
  STRICT_ARGUMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  SLOPPY_ARGUMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  FAST_ALIASED_ARGUMENTS_MAP_INDEX: Slot<NativeContext, Map>,
  FUNCTION_CONTEXT_MAP_INDEX: Slot<NativeContext, Map>,
  FUNCTION_PROTOTYPE_APPLY_INDEX: Slot<NativeContext, JSFunction>,
  STRING_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,

  UINT8_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  INT8_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  UINT16_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  INT16_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  UINT32_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  INT32_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  FLOAT16_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  FLOAT32_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  FLOAT64_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  UINT8_CLAMPED_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  BIGUINT64_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,
  BIGINT64_ARRAY_FUN_INDEX: Slot<NativeContext, JSFunction>,

  RAB_GSAB_UINT8_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_INT8_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_UINT16_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_INT16_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_UINT32_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_INT32_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_FLOAT16_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_FLOAT32_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_FLOAT64_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_UINT8_CLAMPED_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_BIGUINT64_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,
  RAB_GSAB_BIGINT64_ARRAY_MAP_INDEX: Slot<NativeContext, Map>,

  ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX: Slot<NativeContext, Map>,
  DATA_PROPERTY_DESCRIPTOR_MAP_INDEX: Slot<NativeContext, Map>,

  PROMISE_FUNCTION_INDEX: Slot<NativeContext, JSFunction>,
  PROMISE_THEN_INDEX: Slot<NativeContext, JSFunction>,
  PROMISE_PROTOTYPE_INDEX: Slot<NativeContext, JSObject>,
  STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX: Slot<NativeContext, Map>,

  PROMISE_HOOK_INIT_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,
  PROMISE_HOOK_BEFORE_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,
  PROMISE_HOOK_AFTER_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,
  PROMISE_HOOK_RESOLVE_FUNCTION_INDEX: Slot<NativeContext, Undefined|Callable>,

  // @if(V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA)
  CONTINUATION_PRESERVED_EMBEDDER_DATA_INDEX: Slot<NativeContext, HeapObject>,

  BOUND_FUNCTION_WITH_CONSTRUCTOR_MAP_INDEX: Slot<NativeContext, Map>,
  BOUND_FUNCTION_WITHOUT_CONSTRUCTOR_MAP_INDEX: Slot<NativeContext, Map>,

  WRAPPED_FUNCTION_MAP_INDEX: Slot<NativeContext, Map>,

  @sameEnumValueAs(MIN_CONTEXT_SLOTS)
  CONTEXT_SIDE_TABLE_PROPERTY_INDEX: Slot<Context, HeapObject>,

  MIN_CONTEXT_SLOTS,
  MIN_CONTEXT_EXTENDED_SLOTS,
  ...
}

@export
macro LoadContextElement(c: Context, i: intptr): Object {
  return c.elements[i];
}

@export
macro LoadContextElement(c: Context, i: Smi): Object {
  return c.elements[i];
}

@export
macro LoadContextElement(c: Context, i: constexpr int32): Object {
  return c.elements[i];
}

@export
macro LoadScriptContextElement(c: Context, i: intptr): Object {
  return LoadScriptContextElementImpl(c, i);
}

@export
macro LoadScriptContextElement(c: Context, i: Smi): Object {
  return LoadScriptContextElementImpl(c, SmiUntag(i));
}

@export
macro LoadScriptContextElement(c: Context, i: constexpr int32): Object {
  return LoadScriptContextElementImpl(c, i);
}

@export
macro StoreContextElement(c: Context, i: intptr, o: Object): void {
  c.elements[i] = o;
}

@export
macro StoreContextElement(c: Context, i: Smi, o: Object): void {
  c.elements[i] = o;
}

@export
macro StoreContextElement(c: Context, i: constexpr int32, o: Object): void {
  c.elements[i] = o;
}

@export
macro StoreContextElementAndUpdateSideData(
    c: Context, i: intptr, o: Object): void {
  StoreScriptContextAndUpdateSlotProperty(c, i, o);
}

@export
macro StoreContextElementAndUpdateSideData(
    c: Context, i: constexpr int32, o: Object): void {
  StoreScriptContextAndUpdateSlotProperty(c, i, o);
}

builtin AllocateIfMutableHeapNumberScriptContextSlot(
    n: Object, c: Object, i: Smi): JSAny {
  const number = UnsafeCast<HeapNumber>(n);
  const context = UnsafeCast<Context>(c);
  const index = SmiUntag(i);
  if (IsMutableHeapNumber(context, index, number)) {
    return AllocateHeapNumberWithValue(number.value);
  }
  return number;
}

builtin StoreCurrentScriptContextSlotBaseline(o: Object, i: Smi): JSAny {
  const context = internal::LoadContextFromBaseline();
  const index = SmiUntag(i);
  StoreScriptContextAndUpdateSlotProperty(context, index, o);
  return Undefined;
}

builtin StoreScriptContextSlotBaseline(
    c: Object, o: Object, i: Smi, d: TaggedIndex): JSAny {
  let context = UnsafeCast<Context>(c);
  let depth = TaggedIndexToIntPtr(d);
  while (depth > 0) {
    --depth;
    context =
        UnsafeCast<Context>(context.elements[ContextSlot::PREVIOUS_INDEX]);
  }

  const index = SmiUntag(i);
  StoreScriptContextAndUpdateSlotProperty(context, index, o);
  return Undefined;
}

namespace runtime {
extern runtime InvalidateDependentCodeForScriptContextSlot(Context, Object):
    JSAny;
}  // namespace runtime

macro StoreScriptContextAndUpdateSlotProperty(
    c: Context, index: intptr, newValue: Object): void {
  const scriptContext = Cast<ScriptContext>(c) otherwise unreachable;

  const sideDataIndex = index - ContextSlot::MIN_CONTEXT_EXTENDED_SLOTS;
  const sideData: Object = *ContextSlot(
      scriptContext, ContextSlot::CONTEXT_SIDE_TABLE_PROPERTY_INDEX);

  const sideDataFixedArray: FixedArray =
      Cast<FixedArray>(sideData) otherwise return;
  if (sideDataFixedArray.length == 0) {
    // No side data (maybe the const tracking let flag is not on).
    return;
  }

  const oldValue = c.elements[index];
  if (oldValue == TheHole) {
    // Setting the initial value.
    dcheck(sideDataFixedArray.objects[sideDataIndex] == Undefined);
    sideDataFixedArray.objects[sideDataIndex] =
        SmiTag(kContextSidePropertyConst);
    c.elements[index] = newValue;
    return;
  }

  // If we are assigning the same value, the property won't change.
  if (TaggedEqual(oldValue, newValue)) {
    return;
  }
  // If both values are HeapNumbers with the same double value, the property
  // won't change either.
  if (Is<HeapNumber>(oldValue) && Is<HeapNumber>(newValue)) {
    const oldNumber = Cast<HeapNumber>(oldValue) otherwise unreachable;
    const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
    if (oldNumber.value == newNumber.value && oldNumber.value != 0) {
      return;
    }
  }

  // From now on, we know the value is no longer a constant.

  const data = sideDataFixedArray.objects[sideDataIndex];
  let maybeCell: Undefined|ContextSidePropertyCell;
  let property: intptr;

  // From now on, we know the value is no longer a constant. If there's a
  // DependentCode, invalidate it.

  typeswitch (data) {
    case (property_raw: Smi): {
      maybeCell = Undefined;
      property = SmiUntag(property_raw);
    }
    case (cell: ContextSidePropertyCell): {
      maybeCell = cell;
      property = SmiUntag(cell.property_details_raw);
    }
    case (Object): {
      // If this is reached, there's a code path which initializes or assigns a
      // top-level `let` variable but doesn't update the side data.
      unreachable;
    }
  }

  if (property == kContextSidePropertyConst) {
    if (Is<ContextSidePropertyCell>(maybeCell)) {
      runtime::InvalidateDependentCodeForScriptContextSlot(c, maybeCell);
    }
    if (IsScriptContextMutableHeapNumberFlag()) {
      // It can transition to Smi, MutableHeapNumber or Other.
      if (Is<HeapNumber>(newValue)) {
        sideDataFixedArray.objects[sideDataIndex] =
            SmiTag(kContextSidePropertyHeapNumber);
        const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
        c.elements[index] = AllocateHeapNumberWithValue(newNumber.value);
      } else {
        if (Is<Smi>(newValue)) {
          sideDataFixedArray.objects[sideDataIndex] =
              SmiTag(kContextSidePropertySmi);
        } else {
          sideDataFixedArray.objects[sideDataIndex] =
              SmiTag(kContextSidePropertyOther);
        }
        c.elements[index] = newValue;
      }
    } else {
      // MutableHeapNumber is not supported, just transition the property to
      // kOther.
      sideDataFixedArray.objects[sideDataIndex] =
          SmiTag(kContextSidePropertyOther);
      c.elements[index] = newValue;
    }
  } else if (property == kContextSidePropertySmi) {
    if (Is<Smi>(newValue)) {
      c.elements[index] = newValue;
    } else {
      if (Is<ContextSidePropertyCell>(maybeCell)) {
        runtime::InvalidateDependentCodeForScriptContextSlot(c, maybeCell);
      }
      // It can transition to a MutableHeapNumber or Other.
      if (Is<HeapNumber>(newValue)) {
        sideDataFixedArray.objects[sideDataIndex] =
            SmiTag(kContextSidePropertyHeapNumber);
        const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
        c.elements[index] = AllocateHeapNumberWithValue(newNumber.value);
      } else {
        sideDataFixedArray.objects[sideDataIndex] =
            SmiTag(kContextSidePropertyOther);
        c.elements[index] = newValue;
      }
    }
  } else if (property == kContextSidePropertyHeapNumber) {
    const oldNumber = Cast<HeapNumber>(oldValue) otherwise unreachable;
    if (Is<Smi>(newValue)) {
      const newNumber = Cast<Smi>(newValue) otherwise unreachable;
      oldNumber.value = SmiToFloat64(newNumber);
    } else if (Is<HeapNumber>(newValue)) {
      const newNumber = Cast<HeapNumber>(newValue) otherwise unreachable;
      oldNumber.value = newNumber.value;
    } else {
      if (Is<ContextSidePropertyCell>(maybeCell)) {
        runtime::InvalidateDependentCodeForScriptContextSlot(c, maybeCell);
      }
      // It can only transition to Other.
      sideDataFixedArray.objects[sideDataIndex] =
          SmiTag(kContextSidePropertyOther);
      c.elements[index] = newValue;
    }
  } else {
    dcheck(property == kContextSidePropertyOther);
    // We should not have a code depending on Other.
    dcheck(IsUndefined(maybeCell));
    // No need to update side data, this is a sink state...
    c.elements[index] = newValue;
  }
}

macro LoadScriptContextElementImpl(c: Context, i: intptr): Object {
  dcheck(Is<ScriptContext>(c));
  const val = c.elements[i];
  if (IsMutableHeapNumber(c, i, val)) {
    const number = Cast<HeapNumber>(val) otherwise unreachable;
    return AllocateHeapNumberWithValue(number.value);
  }
  return val;
}

macro IsMutableHeapNumber(c: Context, index: intptr, val: Object): bool {
  if (!Is<HeapNumber>(val)) return false;
  const scriptContext = Cast<ScriptContext>(c) otherwise unreachable;

  const sideDataIndex = index - ContextSlot::MIN_CONTEXT_EXTENDED_SLOTS;
  const sideData: Object = *ContextSlot(
      scriptContext, ContextSlot::CONTEXT_SIDE_TABLE_PROPERTY_INDEX);

  const sideDataFixedArray: FixedArray =
      Cast<FixedArray>(sideData) otherwise return false;
  if (sideDataFixedArray.length == 0) {
    // No side data (maybe the const tracking let flag is not on).
    return false;
  }

  typeswitch (sideDataFixedArray.objects[sideDataIndex]) {
    case (Undefined): {
      return false;
    }
    case (cell: ContextSidePropertyCell): {
      return SmiUntag(cell.property_details_raw) ==
          kContextSidePropertyHeapNumber;
    }
    case (property: Smi): {
      return SmiUntag(property) == kContextSidePropertyHeapNumber;
    }
    case (Object): {
      unreachable;
    }
  }
}

// A dummy used instead of a context constant for runtime calls that don't need
// a context.
type NoContext extends Smi;
extern macro NoContextConstant(): NoContext;
const kNoContext: NoContext = NoContextConstant();

"""

```