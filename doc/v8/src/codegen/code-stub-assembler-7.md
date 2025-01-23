Response: The user wants to understand the functionality of the `code-stub-assembler.cc` file in the V8 JavaScript engine. Specifically, they want:

1. **A summary of the file's purpose.**
2. **An explanation of how it relates to JavaScript.**
3. **JavaScript examples to illustrate the connection.**
4. **Confirmation that this is part 8 of a 12-part analysis.**

**Thinking Process:**

1. **Analyze the code snippets:**  Look for recurring patterns and keywords that hint at the file's role. The snippets contain:
    *  `TNode`, `Label`, `Goto`, `Bind`, `Branch`: These suggest a low-level code generation or control flow mechanism.
    *  `LoadMap`, `LoadElements`, `LoadObjectField`, `StoreObjectField`:  Operations related to accessing object properties and structures.
    *  `TryLookupElement`, `TryPrototypeChainLookup`, `HasInPrototypeChain`:  Functions related to property lookup and prototype traversal.
    *  `ElementOffsetFromIndex`, `StoreElementTypedArray`, `LoadFeedbackCellValue`, `UpdateFeedback`: Operations related to accessing and manipulating arrays and performance optimization features.
    *  `CallBuiltin`, `CallRuntime`: Interactions with built-in functions and the runtime system.
    *  `JSObject`, `Map`, `FixedArray`, `String`, `Smi`, `HeapNumber`: References to internal V8 object representations.

2. **Formulate a high-level purpose:** Based on the code analysis, the file seems to be responsible for generating low-level machine code for common JavaScript operations. This code likely optimizes performance by directly manipulating V8's internal object structures.

3. **Identify the connection to JavaScript:**  The file implements fundamental JavaScript concepts like property access, prototype chains, and array operations. The generated code is used when JavaScript code executes these operations.

4. **Develop JavaScript examples:**  Create simple JavaScript code snippets that would trigger the functionality described in the C++ code. Focus on:
    * Property access (`object.property`, `object['property']`).
    * Array access (`array[index]`).
    * Prototype chain interaction (accessing properties of prototype objects).
    * `instanceof` operator (which relates to prototype chains).
    * Typed array operations.

5. **Explain the link between the C++ and JavaScript examples:**  Clearly state how the C++ code is involved in executing the given JavaScript. Emphasize that the C++ code provides optimized implementations for these operations.

6. **Address the part number:** Acknowledge that this is part 8 of 12 and reiterate the core function within this context.

7. **Refine the language:** Ensure the summary is clear, concise, and uses appropriate technical terms.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on specific low-level details. I need to abstract to the core functionality.
* I should ensure the JavaScript examples are simple and directly relate to the C++ concepts. Avoid complex scenarios that might obscure the connection.
* I need to explicitly mention the optimization aspect, as that's a key reason for having a code stub assembler.

By following these steps, I can generate a comprehensive and accurate summary of the `code-stub-assembler.cc` file's functionality and its relation to JavaScript.
Based on the provided C++ code snippets from `v8/src/codegen/code-stub-assembler.cc`, **part 8 of 12**, the primary function of this file is to provide a low-level assembly-like interface for generating optimized machine code stubs within the V8 JavaScript engine.

Here's a breakdown of its key functionalities:

* **Low-Level Code Generation:** The `CodeStubAssembler` class offers a set of methods that resemble assembly instructions (e.g., `Goto`, `Bind`, `Branch`, `Load`, `Store`). This allows developers within V8 to construct sequences of machine instructions directly, offering fine-grained control over the generated code.

* **Optimized Implementations:**  The code snippets demonstrate implementations of core JavaScript operations like:
    * **Property Lookup:**  Functions like `TryLookupElement`, `TryPrototypeChainLookup`, and `HasInPrototypeChain` are responsible for efficiently finding properties on objects, including traversing the prototype chain.
    * **Element Access:** `TryLookupElement` specifically handles looking up elements in arrays and array-like objects, taking into account different element kinds (e.g., packed, holey, double, dictionary).
    * **`instanceof` Operator:** The `OrdinaryHasInstance` function implements the logic for the `instanceof` operator, which checks if an object inherits from another object's prototype.
    * **Typed Array Operations:**  Functions like `ElementOffsetFromIndex`, `StoreElementTypedArray`, and `PrepareValueForWriteToTypedArray` handle the specific logic for accessing and storing elements in Typed Arrays, including type conversions and bounds checking.
    * **Feedback Vector Management:** Functions like `LoadFeedbackCellValue`, `LoadFeedbackVector`, and `UpdateFeedback` are involved in managing feedback vectors, a mechanism used by V8 for optimizing future executions of the same code.

* **Interaction with V8 Internals:** The code directly manipulates V8's internal object representations like `Map` (object structure), `FixedArray` (backing storage for properties and elements), `Smi` (small integers), and `HeapNumber` (floating-point numbers).

* **Code Stubs:** The "code stubs" part of the name implies that this assembler is used to generate small, highly optimized sequences of instructions for specific, frequently executed operations. These stubs are often used as building blocks for more complex code generation or as targets for optimized calls.

**Relationship to JavaScript and Examples:**

This file is directly related to the performance of JavaScript code. When JavaScript code executes, V8 often uses the code stubs generated by this assembler to perform common operations efficiently.

Here are some JavaScript examples illustrating the functionalities implemented in the provided C++ code:

**1. Property Lookup and Prototype Chain:**

```javascript
const proto = { z: 3 };
const obj = Object.create(proto);
obj.x = 1;
obj.y = 2;

console.log(obj.x); // Direct property lookup
console.log(obj.z); // Property lookup through the prototype chain
```

The `TryPrototypeChainLookup` and `HasInPrototypeChain` functions in the C++ code are crucial for efficiently implementing how V8 finds the property `z` on `obj` by traversing the prototype chain to `proto`.

**2. Array Element Access:**

```javascript
const arr = [1, 2, 3];
console.log(arr[1]); // Accessing element at index 1

arr[0] = 4; // Setting element at index 0
```

The `TryLookupElement` function in the C++ code is responsible for the fast and efficient retrieval and setting of elements within the `arr` array. It handles different storage mechanisms V8 might use for arrays.

**3. `instanceof` Operator:**

```javascript
class MyClass {}
const instance = new MyClass();
console.log(instance instanceof MyClass); // true
console.log(instance instanceof Object);  // true
```

The `OrdinaryHasInstance` function in the C++ code implements the logic behind the `instanceof` operator. It checks if the prototype of `MyClass` is present in the prototype chain of `instance`.

**4. Typed Array Operations:**

```javascript
const typedArray = new Uint32Array(2);
typedArray[0] = 10;
typedArray[1] = 20;
console.log(typedArray[0]);
```

Functions like `ElementOffsetFromIndex` and `StoreElementTypedArray` in the C++ code are used to efficiently calculate the memory offset and store the integer value `10` into the `Uint32Array`. `PrepareValueForWriteToTypedArray` handles the necessary type conversion.

**In summary,** `code-stub-assembler.cc` provides the tools and implementations for generating highly optimized machine code for fundamental JavaScript operations. This is essential for the performance of the V8 engine and directly impacts how quickly JavaScript code executes these core operations. Being part 8 of 12 suggests this file focuses on a specific subset of these code generation capabilities within the larger V8 codebase.

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第8部分，共12部分，请归纳一下它的功能
```

### 源代码
```
E_SWISS_NAME_DICTIONARY_BOOL) {
        TNode<Smi> flags =
            GetNameDictionaryFlags<NameDictionary>(CAST(properties));
        GotoIf(IsSetSmi(flags,
                        NameDictionary::MayHaveInterestingPropertiesBit::kMask),
               &lookup);
        *var_holder = LoadMapPrototype(holder_map);
        *var_holder_map = LoadMap((*var_holder).value());
      }
      Goto(&loop);
    }
  }

  BIND(&lookup);
  return CallBuiltin(Builtin::kGetPropertyWithReceiver, context,
                     (*var_holder).value(), name, receiver,
                     SmiConstant(OnNonExistent::kReturnUndefined));
}

void CodeStubAssembler::TryLookupElement(
    TNode<HeapObject> object, TNode<Map> map, TNode<Int32T> instance_type,
    TNode<IntPtrT> intptr_index, Label* if_found, Label* if_absent,
    Label* if_not_found, Label* if_bailout) {
  // Handle special objects in runtime.
  GotoIf(IsSpecialReceiverInstanceType(instance_type), if_bailout);

  TNode<Int32T> elements_kind = LoadMapElementsKind(map);

  // TODO(verwaest): Support other elements kinds as well.
  Label if_isobjectorsmi(this), if_isdouble(this), if_isdictionary(this),
      if_isfaststringwrapper(this), if_isslowstringwrapper(this), if_oob(this),
      if_typedarray(this), if_rab_gsab_typedarray(this);
  // clang-format off
  int32_t values[] = {
      // Handled by {if_isobjectorsmi}.
      PACKED_SMI_ELEMENTS, HOLEY_SMI_ELEMENTS, PACKED_ELEMENTS, HOLEY_ELEMENTS,
      PACKED_NONEXTENSIBLE_ELEMENTS, PACKED_SEALED_ELEMENTS,
      HOLEY_NONEXTENSIBLE_ELEMENTS, HOLEY_SEALED_ELEMENTS,
      PACKED_FROZEN_ELEMENTS, HOLEY_FROZEN_ELEMENTS,
      // Handled by {if_isdouble}.
      PACKED_DOUBLE_ELEMENTS, HOLEY_DOUBLE_ELEMENTS,
      // Handled by {if_isdictionary}.
      DICTIONARY_ELEMENTS,
      // Handled by {if_isfaststringwrapper}.
      FAST_STRING_WRAPPER_ELEMENTS,
      // Handled by {if_isslowstringwrapper}.
      SLOW_STRING_WRAPPER_ELEMENTS,
      // Handled by {if_not_found}.
      NO_ELEMENTS,
      // Handled by {if_typed_array}.
      UINT8_ELEMENTS,
      INT8_ELEMENTS,
      UINT16_ELEMENTS,
      INT16_ELEMENTS,
      UINT32_ELEMENTS,
      INT32_ELEMENTS,
      FLOAT32_ELEMENTS,
      FLOAT64_ELEMENTS,
      UINT8_CLAMPED_ELEMENTS,
      BIGUINT64_ELEMENTS,
      BIGINT64_ELEMENTS,
      RAB_GSAB_UINT8_ELEMENTS,
      RAB_GSAB_INT8_ELEMENTS,
      RAB_GSAB_UINT16_ELEMENTS,
      RAB_GSAB_INT16_ELEMENTS,
      RAB_GSAB_UINT32_ELEMENTS,
      RAB_GSAB_INT32_ELEMENTS,
      RAB_GSAB_FLOAT32_ELEMENTS,
      RAB_GSAB_FLOAT64_ELEMENTS,
      RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
      RAB_GSAB_BIGUINT64_ELEMENTS,
      RAB_GSAB_BIGINT64_ELEMENTS,
  };
  Label* labels[] = {
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi, &if_isobjectorsmi, &if_isobjectorsmi,
      &if_isobjectorsmi,
      &if_isdouble, &if_isdouble,
      &if_isdictionary,
      &if_isfaststringwrapper,
      &if_isslowstringwrapper,
      if_not_found,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
      &if_rab_gsab_typedarray,
  };
  // clang-format on
  static_assert(arraysize(values) == arraysize(labels));
  Switch(elements_kind, if_bailout, values, labels, arraysize(values));

  BIND(&if_isobjectorsmi);
  {
    TNode<FixedArray> elements = CAST(LoadElements(CAST(object)));
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);

    GotoIfNot(UintPtrLessThan(intptr_index, length), &if_oob);

    TNode<Object> element = UnsafeLoadFixedArrayElement(elements, intptr_index);
    TNode<Hole> the_hole = TheHoleConstant();
    Branch(TaggedEqual(element, the_hole), if_not_found, if_found);
  }
  BIND(&if_isdouble);
  {
    TNode<FixedArrayBase> elements = LoadElements(CAST(object));
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);

    GotoIfNot(UintPtrLessThan(intptr_index, length), &if_oob);

    // Check if the element is a double hole, but don't load it.
    LoadFixedDoubleArrayElement(CAST(elements), intptr_index, if_not_found,
                                MachineType::None());
    Goto(if_found);
  }
  BIND(&if_isdictionary);
  {
    // Negative and too-large keys must be converted to property names.
    if (Is64()) {
      GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                             intptr_index),
             if_bailout);
    } else {
      GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), if_bailout);
    }

    TVARIABLE(IntPtrT, var_entry);
    TNode<NumberDictionary> elements = CAST(LoadElements(CAST(object)));
    NumberDictionaryLookup(elements, intptr_index, if_found, &var_entry,
                           if_not_found);
  }
  BIND(&if_isfaststringwrapper);
  {
    TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(CAST(object)));
    TNode<IntPtrT> length = LoadStringLengthAsWord(string);
    GotoIf(UintPtrLessThan(intptr_index, length), if_found);
    Goto(&if_isobjectorsmi);
  }
  BIND(&if_isslowstringwrapper);
  {
    TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(CAST(object)));
    TNode<IntPtrT> length = LoadStringLengthAsWord(string);
    GotoIf(UintPtrLessThan(intptr_index, length), if_found);
    Goto(&if_isdictionary);
  }
  BIND(&if_typedarray);
  {
    TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
    GotoIf(IsDetachedBuffer(buffer), if_absent);

    TNode<UintPtrT> length = LoadJSTypedArrayLength(CAST(object));
    Branch(UintPtrLessThan(intptr_index, length), if_found, if_absent);
  }
  BIND(&if_rab_gsab_typedarray);
  {
    TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
    TNode<UintPtrT> length =
        LoadVariableLengthJSTypedArrayLength(CAST(object), buffer, if_absent);
    Branch(UintPtrLessThan(intptr_index, length), if_found, if_absent);
  }
  BIND(&if_oob);
  {
    // Positive OOB indices mean "not found", negative indices and indices
    // out of array index range must be converted to property names.
    if (Is64()) {
      GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                             intptr_index),
             if_bailout);
    } else {
      GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), if_bailout);
    }
    Goto(if_not_found);
  }
}

void CodeStubAssembler::BranchIfMaybeSpecialIndex(TNode<String> name_string,
                                                  Label* if_maybe_special_index,
                                                  Label* if_not_special_index) {
  // TODO(cwhan.tunz): Implement fast cases more.

  // If a name is empty or too long, it's not a special index
  // Max length of canonical double: -X.XXXXXXXXXXXXXXXXX-eXXX
  const int kBufferSize = 24;
  TNode<Smi> string_length = LoadStringLengthAsSmi(name_string);
  GotoIf(SmiEqual(string_length, SmiConstant(0)), if_not_special_index);
  GotoIf(SmiGreaterThan(string_length, SmiConstant(kBufferSize)),
         if_not_special_index);

  // If the first character of name is not a digit or '-', or we can't match it
  // to Infinity or NaN, then this is not a special index.
  TNode<Int32T> first_char = StringCharCodeAt(name_string, UintPtrConstant(0));
  // If the name starts with '-', it can be a negative index.
  GotoIf(Word32Equal(first_char, Int32Constant('-')), if_maybe_special_index);
  // If the name starts with 'I', it can be "Infinity".
  GotoIf(Word32Equal(first_char, Int32Constant('I')), if_maybe_special_index);
  // If the name starts with 'N', it can be "NaN".
  GotoIf(Word32Equal(first_char, Int32Constant('N')), if_maybe_special_index);
  // Finally, if the first character is not a digit either, then we are sure
  // that the name is not a special index.
  GotoIf(Uint32LessThan(first_char, Int32Constant('0')), if_not_special_index);
  GotoIf(Uint32LessThan(Int32Constant('9'), first_char), if_not_special_index);
  Goto(if_maybe_special_index);
}

void CodeStubAssembler::TryPrototypeChainLookup(
    TNode<Object> receiver, TNode<Object> object_arg, TNode<Object> key,
    const LookupPropertyInHolder& lookup_property_in_holder,
    const LookupElementInHolder& lookup_element_in_holder, Label* if_end,
    Label* if_bailout, Label* if_proxy, bool handle_private_names) {
  // Ensure receiver is JSReceiver, otherwise bailout.
  GotoIf(TaggedIsSmi(receiver), if_bailout);
  TNode<HeapObject> object = CAST(object_arg);

  TNode<Map> map = LoadMap(object);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);
  {
    Label if_objectisreceiver(this);
    Branch(IsJSReceiverInstanceType(instance_type), &if_objectisreceiver,
           if_bailout);
    BIND(&if_objectisreceiver);

    GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), if_proxy);
  }

  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);

  Label if_keyisindex(this), if_iskeyunique(this);
  TryToName(key, &if_keyisindex, &var_index, &if_iskeyunique, &var_unique,
            if_bailout);

  BIND(&if_iskeyunique);
  {
    TVARIABLE(HeapObject, var_holder, object);
    TVARIABLE(Map, var_holder_map, map);
    TVARIABLE(Int32T, var_holder_instance_type, instance_type);

    Label loop(this, {&var_holder, &var_holder_map, &var_holder_instance_type});
    Goto(&loop);
    BIND(&loop);
    {
      TNode<Map> holder_map = var_holder_map.value();
      TNode<Int32T> holder_instance_type = var_holder_instance_type.value();

      Label next_proto(this), check_integer_indexed_exotic(this);
      lookup_property_in_holder(CAST(receiver), var_holder.value(), holder_map,
                                holder_instance_type, var_unique.value(),
                                &check_integer_indexed_exotic, if_bailout);

      BIND(&check_integer_indexed_exotic);
      {
        // Bailout if it can be an integer indexed exotic case.
        GotoIfNot(InstanceTypeEqual(holder_instance_type, JS_TYPED_ARRAY_TYPE),
                  &next_proto);
        GotoIfNot(IsString(var_unique.value()), &next_proto);
        BranchIfMaybeSpecialIndex(CAST(var_unique.value()), if_bailout,
                                  &next_proto);
      }

      BIND(&next_proto);

      if (handle_private_names) {
        // Private name lookup doesn't walk the prototype chain.
        GotoIf(IsPrivateSymbol(CAST(key)), if_end);
      }

      TNode<HeapObject> proto = LoadMapPrototype(holder_map);

      GotoIf(IsNull(proto), if_end);

      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);

      var_holder = proto;
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Goto(&loop);
    }
  }
  BIND(&if_keyisindex);
  {
    TVARIABLE(HeapObject, var_holder, object);
    TVARIABLE(Map, var_holder_map, map);
    TVARIABLE(Int32T, var_holder_instance_type, instance_type);

    Label loop(this, {&var_holder, &var_holder_map, &var_holder_instance_type});
    Goto(&loop);
    BIND(&loop);
    {
      Label next_proto(this);
      lookup_element_in_holder(CAST(receiver), var_holder.value(),
                               var_holder_map.value(),
                               var_holder_instance_type.value(),
                               var_index.value(), &next_proto, if_bailout);
      BIND(&next_proto);

      TNode<HeapObject> proto = LoadMapPrototype(var_holder_map.value());

      GotoIf(IsNull(proto), if_end);

      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);

      var_holder = proto;
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Goto(&loop);
    }
  }
}

TNode<Boolean> CodeStubAssembler::HasInPrototypeChain(TNode<Context> context,
                                                      TNode<HeapObject> object,
                                                      TNode<Object> prototype) {
  TVARIABLE(Boolean, var_result);
  Label return_false(this), return_true(this),
      return_runtime(this, Label::kDeferred), return_result(this);

  // Loop through the prototype chain looking for the {prototype}.
  TVARIABLE(Map, var_object_map, LoadMap(object));
  Label loop(this, &var_object_map);
  Goto(&loop);
  BIND(&loop);
  {
    // Check if we can determine the prototype directly from the {object_map}.
    Label if_objectisdirect(this), if_objectisspecial(this, Label::kDeferred);
    TNode<Map> object_map = var_object_map.value();
    TNode<Uint16T> object_instance_type = LoadMapInstanceType(object_map);
    Branch(IsSpecialReceiverInstanceType(object_instance_type),
           &if_objectisspecial, &if_objectisdirect);
    BIND(&if_objectisspecial);
    {
      // The {object_map} is a special receiver map or a primitive map, check
      // if we need to use the if_objectisspecial path in the runtime.
      GotoIf(InstanceTypeEqual(object_instance_type, JS_PROXY_TYPE),
             &return_runtime);
      TNode<Int32T> object_bitfield = LoadMapBitField(object_map);
      int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                 Map::Bits1::IsAccessCheckNeededBit::kMask;
      Branch(IsSetWord32(object_bitfield, mask), &return_runtime,
             &if_objectisdirect);
    }
    BIND(&if_objectisdirect);

    // Check the current {object} prototype.
    TNode<HeapObject> object_prototype = LoadMapPrototype(object_map);
    GotoIf(IsNull(object_prototype), &return_false);
    GotoIf(TaggedEqual(object_prototype, prototype), &return_true);

    // Continue with the prototype.
    CSA_DCHECK(this, TaggedIsNotSmi(object_prototype));
    var_object_map = LoadMap(object_prototype);
    Goto(&loop);
  }

  BIND(&return_true);
  var_result = TrueConstant();
  Goto(&return_result);

  BIND(&return_false);
  var_result = FalseConstant();
  Goto(&return_result);

  BIND(&return_runtime);
  {
    // Fallback to the runtime implementation.
    var_result = CAST(
        CallRuntime(Runtime::kHasInPrototypeChain, context, object, prototype));
  }
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Boolean> CodeStubAssembler::OrdinaryHasInstance(
    TNode<Context> context, TNode<Object> callable_maybe_smi,
    TNode<Object> object_maybe_smi) {
  TVARIABLE(Boolean, var_result);
  Label return_runtime(this, Label::kDeferred), return_result(this);

  GotoIfForceSlowPath(&return_runtime);

  // Goto runtime if {object} is a Smi.
  GotoIf(TaggedIsSmi(object_maybe_smi), &return_runtime);

  // Goto runtime if {callable} is a Smi.
  GotoIf(TaggedIsSmi(callable_maybe_smi), &return_runtime);

  {
    // Load map of {callable}.
    TNode<HeapObject> object = CAST(object_maybe_smi);
    TNode<HeapObject> callable = CAST(callable_maybe_smi);
    TNode<Map> callable_map = LoadMap(callable);

    // Goto runtime if {callable} is not a JSFunction.
    TNode<Uint16T> callable_instance_type = LoadMapInstanceType(callable_map);
    GotoIfNot(IsJSFunctionInstanceType(callable_instance_type),
              &return_runtime);

    GotoIfPrototypeRequiresRuntimeLookup(CAST(callable), callable_map,
                                         &return_runtime);

    // Get the "prototype" (or initial map) of the {callable}.
    TNode<HeapObject> callable_prototype = LoadObjectField<HeapObject>(
        callable, JSFunction::kPrototypeOrInitialMapOffset);
    {
      Label no_initial_map(this), walk_prototype_chain(this);
      TVARIABLE(HeapObject, var_callable_prototype, callable_prototype);

      // Resolve the "prototype" if the {callable} has an initial map.
      GotoIfNot(IsMap(callable_prototype), &no_initial_map);
      var_callable_prototype = LoadObjectField<HeapObject>(
          callable_prototype, Map::kPrototypeOffset);
      Goto(&walk_prototype_chain);

      BIND(&no_initial_map);
      // {callable_prototype} is the hole if the "prototype" property hasn't
      // been requested so far.
      Branch(TaggedEqual(callable_prototype, TheHoleConstant()),
             &return_runtime, &walk_prototype_chain);

      BIND(&walk_prototype_chain);
      callable_prototype = var_callable_prototype.value();
    }

    // Loop through the prototype chain looking for the {callable} prototype.
    var_result = HasInPrototypeChain(context, object, callable_prototype);
    Goto(&return_result);
  }

  BIND(&return_runtime);
  {
    // Fallback to the runtime implementation.
    var_result = CAST(CallRuntime(Runtime::kOrdinaryHasInstance, context,
                                  callable_maybe_smi, object_maybe_smi));
  }
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

template <typename TIndex>
TNode<IntPtrT> CodeStubAssembler::ElementOffsetFromIndex(
    TNode<TIndex> index_node, ElementsKind kind, int base_size) {
  // TODO(v8:9708): Remove IntPtrT variant in favor of UintPtrT.
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, TaggedIndex>::value ||
                    std::is_same<TIndex, IntPtrT>::value ||
                    std::is_same<TIndex, UintPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT index nodes are allowed");
  int element_size_shift = ElementsKindToShiftSize(kind);
  int element_size = 1 << element_size_shift;
  intptr_t index = 0;
  TNode<IntPtrT> intptr_index_node;
  bool constant_index = false;
  if (std::is_same<TIndex, Smi>::value) {
    TNode<Smi> smi_index_node = ReinterpretCast<Smi>(index_node);
    int const kSmiShiftBits = kSmiShiftSize + kSmiTagSize;
    element_size_shift -= kSmiShiftBits;
    Tagged<Smi> smi_index;
    constant_index = TryToSmiConstant(smi_index_node, &smi_index);
    if (constant_index) {
      index = smi_index.value();
    } else {
      if (COMPRESS_POINTERS_BOOL) {
        smi_index_node = NormalizeSmiIndex(smi_index_node);
      }
    }
    intptr_index_node = BitcastTaggedToWordForTagAndSmiBits(smi_index_node);
  } else if (std::is_same<TIndex, TaggedIndex>::value) {
    TNode<TaggedIndex> tagged_index_node =
        ReinterpretCast<TaggedIndex>(index_node);
    element_size_shift -= kSmiTagSize;
    intptr_index_node = BitcastTaggedToWordForTagAndSmiBits(tagged_index_node);
    constant_index = TryToIntPtrConstant(intptr_index_node, &index);
  } else {
    intptr_index_node = ReinterpretCast<IntPtrT>(index_node);
    constant_index = TryToIntPtrConstant(intptr_index_node, &index);
  }
  if (constant_index) {
    return IntPtrConstant(base_size + element_size * index);
  }

  TNode<IntPtrT> shifted_index =
      (element_size_shift == 0)
          ? intptr_index_node
          : ((element_size_shift > 0)
                 ? WordShl(intptr_index_node,
                           IntPtrConstant(element_size_shift))
                 : WordSar(intptr_index_node,
                           IntPtrConstant(-element_size_shift)));
  return IntPtrAdd(IntPtrConstant(base_size), Signed(shifted_index));
}

// Instantiate ElementOffsetFromIndex for Smi and IntPtrT.
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<Smi>(TNode<Smi> index_node,
                                               ElementsKind kind,
                                               int base_size);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<TaggedIndex>(
    TNode<TaggedIndex> index_node, ElementsKind kind, int base_size);
template V8_EXPORT_PRIVATE TNode<IntPtrT>
CodeStubAssembler::ElementOffsetFromIndex<IntPtrT>(TNode<IntPtrT> index_node,
                                                   ElementsKind kind,
                                                   int base_size);

TNode<BoolT> CodeStubAssembler::IsOffsetInBounds(TNode<IntPtrT> offset,
                                                 TNode<IntPtrT> length,
                                                 int header_size,
                                                 ElementsKind kind) {
  // Make sure we point to the last field.
  int element_size = 1 << ElementsKindToShiftSize(kind);
  int correction = header_size - kHeapObjectTag - element_size;
  TNode<IntPtrT> last_offset = ElementOffsetFromIndex(length, kind, correction);
  return IntPtrLessThanOrEqual(offset, last_offset);
}

TNode<HeapObject> CodeStubAssembler::LoadFeedbackCellValue(
    TNode<JSFunction> closure) {
  TNode<FeedbackCell> feedback_cell =
      LoadObjectField<FeedbackCell>(closure, JSFunction::kFeedbackCellOffset);
  return LoadObjectField<HeapObject>(feedback_cell, FeedbackCell::kValueOffset);
}

TNode<HeapObject> CodeStubAssembler::LoadFeedbackVector(
    TNode<JSFunction> closure) {
  TVARIABLE(HeapObject, maybe_vector);
  Label if_no_feedback_vector(this), out(this);

  maybe_vector = LoadFeedbackVector(closure, &if_no_feedback_vector);
  Goto(&out);

  BIND(&if_no_feedback_vector);
  // If the closure doesn't have a feedback vector allocated yet, return
  // undefined. The FeedbackCell can contain Undefined / FixedArray (for lazy
  // allocations) / FeedbackVector.
  maybe_vector = UndefinedConstant();
  Goto(&out);

  BIND(&out);
  return maybe_vector.value();
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVector(
    TNode<JSFunction> closure, Label* if_no_feedback_vector) {
  TNode<HeapObject> maybe_vector = LoadFeedbackCellValue(closure);
  GotoIfNot(IsFeedbackVector(maybe_vector), if_no_feedback_vector);
  return CAST(maybe_vector);
}

TNode<ClosureFeedbackCellArray> CodeStubAssembler::LoadClosureFeedbackArray(
    TNode<JSFunction> closure) {
  TVARIABLE(HeapObject, feedback_cell_array, LoadFeedbackCellValue(closure));
  Label end(this);

  // When feedback vectors are not yet allocated feedback cell contains
  // an array of feedback cells used by create closures.
  GotoIf(HasInstanceType(feedback_cell_array.value(),
                         CLOSURE_FEEDBACK_CELL_ARRAY_TYPE),
         &end);

  // Load FeedbackCellArray from feedback vector.
  TNode<FeedbackVector> vector = CAST(feedback_cell_array.value());
  feedback_cell_array = CAST(
      LoadObjectField(vector, FeedbackVector::kClosureFeedbackCellArrayOffset));
  Goto(&end);

  BIND(&end);
  return CAST(feedback_cell_array.value());
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVectorForStub() {
  TNode<JSFunction> function =
      CAST(LoadFromParentFrame(StandardFrameConstants::kFunctionOffset));
  return CAST(LoadFeedbackVector(function));
}

TNode<BytecodeArray> CodeStubAssembler::LoadBytecodeArrayFromBaseline() {
  return CAST(
      LoadFromParentFrame(BaselineFrameConstants::kBytecodeArrayFromFp));
}

TNode<FeedbackVector> CodeStubAssembler::LoadFeedbackVectorFromBaseline() {
  return CAST(
      LoadFromParentFrame(BaselineFrameConstants::kFeedbackVectorFromFp));
}

TNode<Context> CodeStubAssembler::LoadContextFromBaseline() {
  return CAST(LoadFromParentFrame(InterpreterFrameConstants::kContextOffset));
}

TNode<FeedbackVector>
CodeStubAssembler::LoadFeedbackVectorForStubWithTrampoline() {
  TNode<RawPtrT> frame_pointer = LoadParentFramePointer();
  TNode<RawPtrT> parent_frame_pointer = Load<RawPtrT>(frame_pointer);
  TNode<JSFunction> function = CAST(
      LoadFullTagged(parent_frame_pointer,
                     IntPtrConstant(StandardFrameConstants::kFunctionOffset)));
  return CAST(LoadFeedbackVector(function));
}

void CodeStubAssembler::UpdateFeedback(TNode<Smi> feedback,
                                       TNode<HeapObject> maybe_feedback_vector,
                                       TNode<UintPtrT> slot_id,
                                       UpdateFeedbackMode mode) {
  switch (mode) {
    case UpdateFeedbackMode::kOptionalFeedback:
      MaybeUpdateFeedback(feedback, maybe_feedback_vector, slot_id);
      break;
    case UpdateFeedbackMode::kGuaranteedFeedback:
      CSA_DCHECK(this, IsFeedbackVector(maybe_feedback_vector));
      UpdateFeedback(feedback, CAST(maybe_feedback_vector), slot_id);
      break;
    case UpdateFeedbackMode::kNoFeedback:
#ifdef V8_JITLESS
      CSA_DCHECK(this, IsUndefined(maybe_feedback_vector));
      break;
#else
      UNREACHABLE();
#endif  // !V8_JITLESS
  }
}

void CodeStubAssembler::MaybeUpdateFeedback(TNode<Smi> feedback,
                                            TNode<HeapObject> maybe_vector,
                                            TNode<UintPtrT> slot_id) {
  Label end(this);
  GotoIf(IsUndefined(maybe_vector), &end);
  {
    UpdateFeedback(feedback, CAST(maybe_vector), slot_id);
    Goto(&end);
  }
  BIND(&end);
}

void CodeStubAssembler::UpdateFeedback(TNode<Smi> feedback,
                                       TNode<FeedbackVector> feedback_vector,
                                       TNode<UintPtrT> slot_id) {
  Label end(this);

  // This method is used for binary op and compare feedback. These
  // vector nodes are initialized with a smi 0, so we can simply OR
  // our new feedback in place.
  TNode<MaybeObject> feedback_element =
      LoadFeedbackVectorSlot(feedback_vector, slot_id);
  TNode<Smi> previous_feedback = CAST(feedback_element);
  TNode<Smi> combined_feedback = SmiOr(previous_feedback, feedback);

  GotoIf(SmiEqual(previous_feedback, combined_feedback), &end);
  {
    StoreFeedbackVectorSlot(feedback_vector, slot_id, combined_feedback,
                            SKIP_WRITE_BARRIER);
    ReportFeedbackUpdate(feedback_vector, slot_id, "UpdateFeedback");
    Goto(&end);
  }

  BIND(&end);
}

void CodeStubAssembler::ReportFeedbackUpdate(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot_id,
    const char* reason) {
#ifdef V8_TRACE_FEEDBACK_UPDATES
  // Trace the update.
  CallRuntime(Runtime::kTraceUpdateFeedback, NoContextConstant(),
              feedback_vector, SmiTag(Signed(slot_id)), StringConstant(reason));
#endif  // V8_TRACE_FEEDBACK_UPDATES
}

void CodeStubAssembler::OverwriteFeedback(TVariable<Smi>* existing_feedback,
                                          int new_feedback) {
  if (existing_feedback == nullptr) return;
  *existing_feedback = SmiConstant(new_feedback);
}

void CodeStubAssembler::CombineFeedback(TVariable<Smi>* existing_feedback,
                                        int feedback) {
  if (existing_feedback == nullptr) return;
  *existing_feedback = SmiOr(existing_feedback->value(), SmiConstant(feedback));
}

void CodeStubAssembler::CombineFeedback(TVariable<Smi>* existing_feedback,
                                        TNode<Smi> feedback) {
  if (existing_feedback == nullptr) return;
  *existing_feedback = SmiOr(existing_feedback->value(), feedback);
}

void CodeStubAssembler::CheckForAssociatedProtector(TNode<Name> name,
                                                    Label* if_protector) {
  // This list must be kept in sync with LookupIterator::UpdateProtector!
  auto first_ptr = Unsigned(
      BitcastTaggedToWord(LoadRoot(RootIndex::kFirstNameForProtector)));
  auto last_ptr =
      Unsigned(BitcastTaggedToWord(LoadRoot(RootIndex::kLastNameForProtector)));
  auto name_ptr = Unsigned(BitcastTaggedToWord(name));
  GotoIf(IsInRange(name_ptr, first_ptr, last_ptr), if_protector);
}

void CodeStubAssembler::DCheckReceiver(ConvertReceiverMode mode,
                                       TNode<Object> receiver) {
  switch (mode) {
    case ConvertReceiverMode::kNullOrUndefined:
      CSA_DCHECK(this, IsNullOrUndefined(receiver));
      break;
    case ConvertReceiverMode::kNotNullOrUndefined:
      CSA_DCHECK(this, Word32BinaryNot(IsNullOrUndefined(receiver)));
      break;
    case ConvertReceiverMode::kAny:
      break;
  }
}

TNode<Map> CodeStubAssembler::LoadReceiverMap(TNode<Object> receiver) {
  TVARIABLE(Map, value);
  Label vtrue(this, Label::kDeferred), vfalse(this), end(this);
  Branch(TaggedIsSmi(receiver), &vtrue, &vfalse);

  BIND(&vtrue);
  {
    value = HeapNumberMapConstant();
    Goto(&end);
  }
  BIND(&vfalse);
  {
    value = LoadMap(UncheckedCast<HeapObject>(receiver));
    Goto(&end);
  }

  BIND(&end);
  return value.value();
}

TNode<IntPtrT> CodeStubAssembler::TryToIntptr(
    TNode<Object> key, Label* if_not_intptr,
    TVariable<Int32T>* var_instance_type) {
  TVARIABLE(IntPtrT, var_intptr_key);
  Label done(this, &var_intptr_key), key_is_smi(this), key_is_heapnumber(this);
  GotoIf(TaggedIsSmi(key), &key_is_smi);

  TNode<Int32T> instance_type = LoadInstanceType(CAST(key));
  if (var_instance_type != nullptr) {
    *var_instance_type = instance_type;
  }

  Branch(IsHeapNumberInstanceType(instance_type), &key_is_heapnumber,
         if_not_intptr);

  BIND(&key_is_smi);
  {
    var_intptr_key = SmiUntag(CAST(key));
    Goto(&done);
  }

  BIND(&key_is_heapnumber);
  {
    TNode<Float64T> value = LoadHeapNumberValue(CAST(key));
#if V8_TARGET_ARCH_64_BIT
    TNode<IntPtrT> int_value =
        TNode<IntPtrT>::UncheckedCast(TruncateFloat64ToInt64(value));
#else
    TNode<IntPtrT> int_value =
        TNode<IntPtrT>::UncheckedCast(RoundFloat64ToInt32(value));
#endif
    GotoIfNot(Float64Equal(value, RoundIntPtrToFloat64(int_value)),
              if_not_intptr);
#if V8_TARGET_ARCH_64_BIT
    // We can't rely on Is64() alone because 32-bit compilers rightly complain
    // about kMaxSafeIntegerUint64 not fitting into an intptr_t.
    DCHECK(Is64());
    // TODO(jkummerow): Investigate whether we can drop support for
    // negative indices.
    GotoIfNot(IsInRange(int_value, static_cast<intptr_t>(-kMaxSafeInteger),
                        static_cast<intptr_t>(kMaxSafeIntegerUint64)),
              if_not_intptr);
#else
    DCHECK(!Is64());
#endif
    var_intptr_key = int_value;
    Goto(&done);
  }

  BIND(&done);
  return var_intptr_key.value();
}

TNode<Context> CodeStubAssembler::LoadScriptContext(
    TNode<Context> context, TNode<IntPtrT> context_index) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<ScriptContextTable> script_context_table = CAST(
      LoadContextElement(native_context, Context::SCRIPT_CONTEXT_TABLE_INDEX));
  return LoadArrayElement(script_context_table, context_index);
}

namespace {

// Converts typed array elements kind to a machine representations.
MachineRepresentation ElementsKindToMachineRepresentation(ElementsKind kind) {
  switch (kind) {
    case UINT8_CLAMPED_ELEMENTS:
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
      return MachineRepresentation::kWord8;
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case FLOAT16_ELEMENTS:
      return MachineRepresentation::kWord16;
    case UINT32_ELEMENTS:
    case INT32_ELEMENTS:
      return MachineRepresentation::kWord32;
    case FLOAT32_ELEMENTS:
      return MachineRepresentation::kFloat32;
    case FLOAT64_ELEMENTS:
      return MachineRepresentation::kFloat64;
    default:
      UNREACHABLE();
  }
}

}  // namespace

// TODO(solanes): Since we can't use `if constexpr` until we enable C++17 we
// have to specialize the BigInt and Word32T cases. Since we can't partly
// specialize, we have to specialize all used combinations.
template <typename TIndex>
void CodeStubAssembler::StoreElementTypedArrayBigInt(TNode<RawPtrT> elements,
                                                     ElementsKind kind,
                                                     TNode<TIndex> index,
                                                     TNode<BigInt> value) {
  static_assert(std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only UintPtrT or IntPtrT indices is allowed");
  DCHECK(kind == BIGINT64_ELEMENTS || kind == BIGUINT64_ELEMENTS);
  TNode<IntPtrT> offset = ElementOffsetFromIndex(index, kind, 0);
  TVARIABLE(UintPtrT, var_low);
  // Only used on 32-bit platforms.
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value, &var_low, &var_high);

  MachineRepresentation rep = WordT::kMachineRepresentation;
#if defined(V8_TARGET_BIG_ENDIAN)
    if (!Is64()) {
      StoreNoWriteBarrier(rep, elements, offset, var_high.value());
      StoreNoWriteBarrier(rep, elements,
                          IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)),
                          var_low.value());
    } else {
      StoreNoWriteBarrier(rep, elements, offset, var_low.value());
    }
#else
    StoreNoWriteBarrier(rep, elements, offset, var_low.value());
    if (!Is64()) {
      StoreNoWriteBarrier(rep, elements,
                          IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)),
                          var_high.value());
    }
#endif
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<UintPtrT> index,
                                               TNode<BigInt> value) {
  StoreElementTypedArrayBigInt(elements, kind, index, value);
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<IntPtrT> index,
                                               TNode<BigInt> value) {
  StoreElementTypedArrayBigInt(elements, kind, index, value);
}

template <typename TIndex>
void CodeStubAssembler::StoreElementTypedArrayWord32(TNode<RawPtrT> elements,
                                                     ElementsKind kind,
                                                     TNode<TIndex> index,
                                                     TNode<Word32T> value) {
  static_assert(std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only UintPtrT or IntPtrT indices is allowed");
  DCHECK(IsTypedArrayElementsKind(kind));
  if (kind == UINT8_CLAMPED_ELEMENTS) {
    CSA_DCHECK(this, Word32Equal(value, Word32And(Int32Constant(0xFF), value)));
  }
  TNode<IntPtrT> offset = ElementOffsetFromIndex(index, kind, 0);
  // TODO(cbruni): Add OOB check once typed.
  MachineRepresentation rep = ElementsKindToMachineRepresentation(kind);
  StoreNoWriteBarrier(rep, elements, offset, value);
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<UintPtrT> index,
                                               TNode<Word32T> value) {
  StoreElementTypedArrayWord32(elements, kind, index, value);
}

template <>
void CodeStubAssembler::StoreElementTypedArray(TNode<RawPtrT> elements,
                                               ElementsKind kind,
                                               TNode<IntPtrT> index,
                                               TNode<Word32T> value) {
  StoreElementTypedArrayWord32(elements, kind, index, value);
}

template <typename TArray, typename TIndex, typename TValue>
void CodeStubAssembler::StoreElementTypedArray(TNode<TArray> elements,
                                               ElementsKind kind,
                                               TNode<TIndex> index,
                                               TNode<TValue> value) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT indices is allowed");
  static_assert(std::is_same<TArray, RawPtrT>::value ||
                    std::is_same<TArray, FixedArrayBase>::value,
                "Only RawPtrT or FixedArrayBase elements are allowed");
  static_assert(std::is_same<TValue, Float16RawBitsT>::value ||
                    std::is_same<TValue, Int32T>::value ||
                    std::is_same<TValue, Float32T>::value ||
                    std::is_same<TValue, Float64T>::value ||
                    std::is_same<TValue, Object>::value,
                "Only Int32T, Float32T, Float64T or object value "
                "types are allowed");
  DCHECK(IsTypedArrayElementsKind(kind));
  TNode<IntPtrT> offset = ElementOffsetFromIndex(index, kind, 0);
  // TODO(cbruni): Add OOB check once typed.
  MachineRepresentation rep = ElementsKindToMachineRepresentation(kind);
  StoreNoWriteBarrier(rep, elements, offset, value);
}

template <typename TIndex>
void CodeStubAssembler::StoreElement(TNode<FixedArrayBase> elements,
                                     ElementsKind kind, TNode<TIndex> index,
                                     TNode<Object> value) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");
  DCHECK(!IsDoubleElementsKind(kind));
  if (IsTypedArrayElementsKind(kind)) {
    StoreElementTypedArray(elements, kind, index, value);
  } else if (IsSmiElementsKind(kind)) {
    TNode<Smi> smi_value = CAST(value);
    StoreFixedArrayElement(CAST(elements), index, smi_value);
  } else {
    StoreFixedArrayElement(CAST(elements), index, value);
  }
}

template <typename TIndex>
void CodeStubAssembler::StoreElement(TNode<FixedArrayBase> elements,
                                     ElementsKind kind, TNode<TIndex> index,
                                     TNode<Float64T> value) {
  static_assert(
      std::is_same<TIndex, Smi>::value || std::is_same<TIndex, IntPtrT>::value,
      "Only Smi or IntPtrT indices are allowed");
  DCHECK(IsDoubleElementsKind(kind));
  StoreFixedDoubleArrayElement(CAST(elements), index, value);
}

template <typename TIndex, typename TValue>
void CodeStubAssembler::StoreElement(TNode<RawPtrT> elements, ElementsKind kind,
                                     TNode<TIndex> index, TNode<TValue> value) {
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, IntPtrT>::value ||
                    std::is_same<TIndex, UintPtrT>::value,
                "Only Smi, IntPtrT or UintPtrT indices are allowed");
  static_assert(
      std::is_same<TValue, Float16RawBitsT>::value ||
          std::is_same<TValue, Int32T>::value ||
          std::is_same<TValue, Word32T>::value ||
          std::is_same<TValue, Float32T>::value ||
          std::is_same<TValue, Float64T>::value ||
          std::is_same<TValue, BigInt>::value,
      "Only Int32T, Word32T, Float32T, Float64T or BigInt value types "
      "are allowed");

  DCHECK(IsTypedArrayElementsKind(kind));
  StoreElementTypedArray(elements, kind, index, value);
}
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(TNode<RawPtrT>,
                                                                ElementsKind,
                                                                TNode<UintPtrT>,
                                                                TNode<Int32T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(TNode<RawPtrT>,
                                                                ElementsKind,
                                                                TNode<UintPtrT>,
                                                                TNode<Word32T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(
    TNode<RawPtrT>, ElementsKind, TNode<UintPtrT>, TNode<Float32T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(
    TNode<RawPtrT>, ElementsKind, TNode<UintPtrT>, TNode<Float64T>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(TNode<RawPtrT>,
                                                                ElementsKind,
                                                                TNode<UintPtrT>,
                                                                TNode<BigInt>);
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreElement(
    TNode<RawPtrT>, ElementsKind, TNode<UintPtrT>, TNode<Float16RawBitsT>);

TNode<Uint8T> CodeStubAssembler::Int32ToUint8Clamped(
    TNode<Int32T> int32_value) {
  Label done(this);
  TNode<Int32T> int32_zero = Int32Constant(0);
  TNode<Int32T> int32_255 = Int32Constant(255);
  TVARIABLE(Word32T, var_value, int32_value);
  GotoIf(Uint32LessThanOrEqual(int32_value, int32_255), &done);
  var_value = int32_zero;
  GotoIf(Int32LessThan(int32_value, int32_zero), &done);
  var_value = int32_255;
  Goto(&done);
  BIND(&done);
  return UncheckedCast<Uint8T>(var_value.value());
}

TNode<Uint8T> CodeStubAssembler::Float64ToUint8Clamped(
    TNode<Float64T> float64_value) {
  Label done(this);
  TVARIABLE(Word32T, var_value, Int32Constant(0));
  GotoIf(Float64LessThanOrEqual(float64_value, Float64Constant(0.0)), &done);
  var_value = Int32Constant(255);
  GotoIf(Float64LessThanOrEqual(Float64Constant(255.0), float64_value), &done);
  {
    TNode<Float64T> rounded_value = Float64RoundToEven(float64_value);
    var_value = TruncateFloat64ToWord32(rounded_value);
    Goto(&done);
  }
  BIND(&done);
  return UncheckedCast<Uint8T>(var_value.value());
}

template <>
TNode<Word32T> CodeStubAssembler::PrepareValueForWriteToTypedArray<Word32T>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));

  switch (elements_kind) {
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case UINT32_ELEMENTS:
    case INT32_ELEMENTS:
    case UINT8_CLAMPED_ELEMENTS:
      break;
    default:
      UNREACHABLE();
  }

  TVARIABLE(Word32T, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    TNode<Float64T> value =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    if (elements_kind == UINT8_CLAMPED_ELEMENTS) {
      var_result = Float64ToUint8Clamped(value);
    } else if (elements_kind == FLOAT16_ELEMENTS) {
      var_result = ReinterpretCast<Word32T>(TruncateFloat64ToFloat16(value));
    } else {
      var_result = TruncateFloat64ToWord32(value);
    }
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    if (elements_kind == UINT8_CLAMPED_ELEMENTS) {
      var_result = Int32ToUint8Clamped(value);
    } else if (elements_kind == FLOAT16_ELEMENTS) {
      var_result = ReinterpretCast<Word32T>(RoundInt32ToFloat16(value));
    } else {
      var_result = value;
    }
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<Float16RawBitsT>
CodeStubAssembler::PrepareValueForWriteToTypedArray<Float16RawBitsT>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));
  CHECK_EQ(elements_kind, FLOAT16_ELEMENTS);

  TVARIABLE(Float16RawBitsT, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    TNode<Float64T> value =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    var_result = TruncateFloat64ToFloat16(value);
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    var_result = RoundInt32ToFloat16(value);
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<Float32T> CodeStubAssembler::PrepareValueForWriteToTypedArray<Float32T>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));
  CHECK_EQ(elements_kind, FLOAT32_ELEMENTS);

  TVARIABLE(Float32T, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    TNode<Float64T> value =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    var_result = TruncateFloat64ToFloat32(value);
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    var_result = RoundInt32ToFloat32(value);
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<Float64T> CodeStubAssembler::PrepareValueForWriteToTypedArray<Float64T>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(IsTypedArrayElementsKind(elements_kind));
  CHECK_EQ(elements_kind, FLOAT64_ELEMENTS);

  TVARIABLE(Float64T, var_result);
  TVARIABLE(Object, var_input, input);
  Label done(this, &var_result), if_smi(this), if_heapnumber_or_oddball(this),
      convert(this), loop(this, &var_input);
  Goto(&loop);
  BIND(&loop);
  GotoIf(TaggedIsSmi(var_input.value()), &if_smi);
  // We can handle both HeapNumber and Oddball here, since Oddball has the
  // same layout as the HeapNumber for the HeapNumber::value field. This
  // way we can also properly optimize stores of oddballs to typed arrays.
  TNode<HeapObject> heap_object = CAST(var_input.value());
  GotoIf(IsHeapNumber(heap_object), &if_heapnumber_or_oddball);
  STATIC_ASSERT_FIELD_OFFSETS_EQUAL(offsetof(HeapNumber, value_),
                                    offsetof(Oddball, to_number_raw_));
  Branch(HasInstanceType(heap_object, ODDBALL_TYPE), &if_heapnumber_or_oddball,
         &convert);

  BIND(&if_heapnumber_or_oddball);
  {
    var_result =
        LoadObjectField<Float64T>(heap_object, offsetof(HeapNumber, value_));
    Goto(&done);
  }

  BIND(&if_smi);
  {
    TNode<Int32T> value = SmiToInt32(CAST(var_input.value()));
    var_result = ChangeInt32ToFloat64(value);
    Goto(&done);
  }

  BIND(&convert);
  {
    var_input = CallBuiltin(Builtin::kNonNumberToNumber, context, input);
    Goto(&loop);
  }

  BIND(&done);
  return var_result.value();
}

template <>
TNode<BigInt> CodeStubAssembler::PrepareValueForWriteToTypedArray<BigInt>(
    TNode<Object> input, ElementsKind elements_kind, TNode<Context> context) {
  DCHECK(elements_kind == BIGINT64_ELEMENTS ||
         elements_kind == BIGUINT64_ELEMENTS);
  return ToBigInt(context, input);
}

#if V8_ENABLE_WEBASSEMBLY
TorqueStructInt64AsInt32Pair CodeStubAssembler::BigIntToRawBytes(
    TNode<BigInt> value) {
  TVARIABLE(UintPtrT, var_low);
  // Only used on 32-bit platforms.
  TVARIABLE(UintPtrT, var_high);
  BigIntToRawBytes(value, &var_low, &var_high);
  return {var_low.value(), var_high.value()};
}
#endif  // V8_ENABLE_WEBASSEMBLY

void CodeStubAssembler::BigIntToRawBytes(TNode<BigInt> bigint,
                                         TVariable<UintPtrT>* var_low,
                                         TVariable<UintPtrT>* var_high) {
  Label done(this);
  *var_low = Unsigned(IntPtrConstant(0));
  *var_high = Unsigned(IntPtrConstant(0));
  TNode<Word32T> bitfield = LoadBigIntBitfield(bigint);
  TNode<Uint32T> length = DecodeWord32<BigIntBase::LengthBits>(bitfield);
  TNode<Uint32T> sign = DecodeWord32<BigIntBase::SignBits>(bitfield);
  GotoIf(Word32Equal(length, Int32Constant(0)), &done);
  *var_low = LoadBigIntDigit(bigint, 0);
  if (!Is64()) {
    Label load_done(this);
    GotoIf(Word32Equal(length, Int32Constant(1)), &load_done);
    *var_high = LoadBigIntDigit(bigint, 1);
    Goto(&load_done);
    BIND(&load_done);
  }
  GotoIf(Word32Equal(sign, Int32Constant(0)), &done);
  // Negative value. Simulate two's complement.
  if (!Is64()) {
    *var_high = Unsigned(IntPtrSub(IntPtrConstant(0), var_high->value()));
    Label no_carry(this);
    GotoIf(IntPtrEqual(var_low->value(), IntPtrConstant(0)), &no_carry);
    *var_high = Unsigned(IntPtrSub(var_high->value(), IntPtrConstant(1)));
    Goto(&no_carry);
    BIND(&no_carry);
  }
  *var_low = Unsigned(IntPtrSub(IntPtrConstant(0), var_low->value()));
  Goto(&done);
  BIND(&done);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Word32T> converted_value, TVariable<Object>* maybe_converted_value) {
  switch (elements_kind) {
    case UINT8_ELEMENTS:
    case INT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case INT16_ELEMENTS:
    case UINT8_CLAMPED_ELEMENTS:
      *maybe_converted_value =
          SmiFromInt32(UncheckedCast<Int32T>(converted_value));
      break;
    case UINT32_ELEMENTS:
      *maybe_converted_value =
          ChangeUint32ToTagged(UncheckedCast<Uint32T>(converted_value));
      break;
    case INT32_ELEMENTS:
      *maybe_converted_value =
          ChangeInt32ToTagged(UncheckedCast<Int32T>(converted_value));
      break;
    default:
      UNREACHABLE();
  }
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Float16RawBitsT> converted_value,
    TVariable<Object>* maybe_converted_value) {
  Label dont_allocate_heap_number(this), end(this);
  GotoIf(TaggedIsSmi(value), &dont_allocate_heap_number);
  GotoIf(IsHeapNumber(CAST(value)), &dont_allocate_heap_number);
  {
    *maybe_converted_value =
        AllocateHeapNumberWithValue(ChangeFloat16ToFloat64(converted_value));
    Goto(&end);
  }
  BIND(&dont_allocate_heap_number);
  {
    *maybe_converted_value = value;
    Goto(&end);
  }
  BIND(&end);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Float32T> converted_value, TVariable<Object>* maybe_converted_value) {
  Label dont_allocate_heap_number(this), end(this);
  GotoIf(TaggedIsSmi(value), &dont_allocate_heap_number);
  GotoIf(IsHeapNumber(CAST(value)), &dont_allocate_heap_number);
  {
    *maybe_converted_value =
        AllocateHeapNumberWithValue(ChangeFloat32ToFloat64(converted_value));
    Goto(&end);
  }
  BIND(&dont_allocate_heap_number);
  {
    *maybe_converted_value = value;
    Goto(&end);
  }
  BIND(&end);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<Float64T> converted_value, TVariable<Object>* maybe_converted_value) {
  Label dont_allocate_heap_number(this), end(this);
  GotoIf(TaggedIsSmi(value), &dont_allocate_heap_number);
  GotoIf(IsHeapNumber(CAST(value)), &dont_allocate_heap_number);
  {
    *maybe_converted_value = AllocateHeapNumberWithValue(converted_value);
    Goto(&end);
  }
  BIND(&dont_allocate_heap_number);
  {
    *maybe_converted_value = value;
    Goto(&end);
  }
  BIND(&end);
}

template <>
void CodeStubAssembler::EmitElementStoreTypedArrayUpdateValue(
    TNode<Object> value, ElementsKind elements_kind,
    TNode<BigInt> converted_value, TVariable<Object>* maybe_converted_value) {
  *maybe_converted_value = converted_value;
}

template <typename TValue>
void CodeStubAssembler::EmitElementStoreTypedArray(
    TNode<JSTypedArray> typed_array, TNode<IntPtrT> key, TNode<Object> value,
    ElementsKind elements_kind, KeyedAccessStoreMode store_mode, Label* bailout,
    TNode<Context> context, TVariable<Object>* maybe_converted_value) {
  Label done(this), update_value_and_bailout(this, Label::kDeferred);

  bool is_rab_gsab = false;
  if (IsRabGsabTypedArrayElementsKind(elements_kind)) {
    is_rab_gsab = true;
    // For the rest of the function, use the corresponding non-RAB/GSAB
    // ElementsKind.
    elements_kind = GetCorrespondingNonRabGsabElementsKind(elements_kind);
  }

  TNode<TValue> converted_value =
      PrepareValueForWriteToTypedArray<TValue>(value, elements_kind, context);

  // There must be no allocations between the buffer load and
  // and the actual store to backing store, because GC may decide that
  // the buffer is not alive or move the elements.
  // TODO(ishell): introduce DisallowGarbageCollectionCode scope here.

  // Check if buffer has been detached. (For RAB / GSAB this is part of loading
  // the length, so no additional check is needed.)
  TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(typed_array);
  if (!is_rab_gsab) {
    GotoIf(IsDetachedBuffer(buffer), &update_value_and_bailout);
  }

  // Bounds check.
  TNode<UintPtrT> length;
  if (is_rab_gsab) {
    length = LoadVariableLengthJSTypedArrayLength(
        typed_array, buffer,
        StoreModeIgnoresTypeArrayOOB(store_mode) ? &done
                                                 : &update_value_and_bailout);
  } else {
    length = LoadJSTypedArrayLength(typed_array);
  }

  if (StoreModeIgnoresTypeArrayOOB(store_mode)) {
    // Skip the store if we write beyond the length or
    // to a property with a negative integer index.
    GotoIfNot(UintPtrLessThan(key, length), &done);
  } else {
    DCHECK(StoreModeIsInBounds(store_mode));
    GotoIfNot(UintPtrLessThan(key, length), &update_value_and_bailout);
  }

  TNode<RawPtrT> data_ptr = LoadJSTypedArrayDataPtr(typed_array);
  StoreElement(data_ptr, elements_kind, key, converted_value);
  Goto(&done);

  if (!is_rab_gsab || !StoreModeIgnoresTypeArrayOOB(store_mode)) {
    BIND(&update_value_and_bailout);
    // We already prepared the incoming value for storing into a typed array.
    // This might involve calling ToNumber in some cases. We shouldn't call
    // ToNumber again in the runtime so pass the converted value to the runtime.
    // The prepared value is an untagged value. Convert it to a tagged value
    // to pass it to runtime. It is not possible to do the detached buffer check
    // before we prepare the value, since ToNumber can detach the ArrayBuffer.
    // The spec specifies the order of these operations.
    if (maybe_converted_value != nullptr) {
      EmitElementStoreTypedArrayUpdateValue(
          value, elements_kind, converted_value, maybe_converted_value);
    }
    Goto(bailout);
  }

  BIND(&done);
}

void CodeStubAssembler::EmitElementStore(
    TNode<JSObject> object, TNode<Object> key, TNode<Object> value,
    ElementsKind elements_kind, KeyedAccessStoreMode store_mode, Label* bailout,
    TNode<Context> context, TVariable<Object>* maybe_converted_value) {
  CSA_DCHECK(this, Word32BinaryNot(IsJSProxy(object)));

  TNode<FixedArrayBase> elements = LoadElements(object);
  if (!(IsSmiOrObjectElementsKind(elements_kind) ||
        IsSealedElementsKind(elements_kind) ||
        IsNonextensibleElementsKind(elements_kind))) {
    CSA_DCHECK(this, Word32BinaryNot(IsFixedCOWArrayMap(LoadMap(elements))));
  } else if (!StoreModeHandlesCOW(store_mode)) {
    GotoIf(IsFixedCOWArrayMap(LoadMap(elements)), bailout);
  }

  // TODO(ishell): introduce TryToIntPtrOrSmi() and use BInt.
  TNode<IntPtrT> intptr_key = TryToIntptr(key, bailout);

  // TODO(rmcilroy): TNodify the converted value once this funciton and
  // StoreElement are templated based on the type elements_kind type.
  if (IsTypedArrayOrRabGsabTypedArrayElementsKind(elements_kind)) {
    TNode<JSTypedArray> typed_array = CAST(object);
    switch (elements_kind) {
      case UINT8_ELEMENTS:
      case INT8_ELEMENTS:
      case UINT16_ELEMENTS:
      case INT16_ELEMENTS:
      case UINT32_ELEMENTS:
      case INT32_ELEMENTS:
      case UINT8_CLAMPED_ELEMENTS:
      case RAB_GSAB_UINT8_ELEMENTS:
      case RAB_GSAB_INT8_ELEMENTS:
      case RAB_GSAB_UINT16_ELEMENTS:
      case RAB_GSAB_INT16_ELEMENTS:
      case RAB_GSAB_UINT32_ELEMENTS:
      case RAB_GSAB_INT32_ELEMENTS:
      case RAB_GSAB_UINT8_CLAMPED_ELEMENTS:
        EmitElementStoreTypedArray<Word32T>(typed_array, intptr_key, value,
                                            elements_kind, store_mode, bailout,
                                            context, maybe_converted_value);
        break;
      case FLOAT32_ELEMENTS:
      case RAB_GSAB_FLOAT32_ELEMENTS:
        EmitElementStoreTypedArray<Float32T>(typed_array, intptr_key, value,
                                             elements_kind, store_mode, bailout,
                                             context, maybe_converted_value);
        break;
      case FLOAT64_ELEMENTS:
      case RAB_GSAB_FLOAT64_ELEMENTS:
        EmitElementStoreTypedArray<Float64T>(typed_array, intptr_key, value,
                                             elements_kind, store_mode, bailout,
                                             context, maybe_converted_value);
        break;
      case BIGINT64_ELEMENTS:
      case BIGUINT64_ELEMENTS:
      case RAB_GSAB_BIGINT64_ELEMENTS:
      case RAB_GSAB_BIGUINT64_ELEMENTS:
        EmitElementStoreTypedArray<BigInt>(typed_array, intptr_key, value,
                                           elements_kind, store_mode, bailout,
                                           context, maybe_converted_value);
        break;
      case FLOAT16_ELEMENTS:
      case RAB_GSAB_FLOAT16_ELEMENTS:
        EmitElementStoreTypedArray<Float16RawBitsT>(
            typed_array, intptr_key, value, elements_kind, store_mode, bailout,
            context, maybe_converted_value);
        break;
      default:
        UNREACHABLE();
    }
    return;
  }
  DCHECK(IsFastElementsKind(elements_kind) ||
         IsSealedElementsKind(elements_kind) ||
         IsNonextensibleElementsKind(elements_kind));

  // In case value is stored into a fast smi array, assure that the value is
  // a smi before manipulating the backing store. Otherwise the backing store
  // may be left in an invalid state.
  std::optional<TNode<Float64T>> float_value;
  if (IsSmiElementsKind(elements_kind)) {
    GotoIfNot(TaggedIsSmi(value), bailout);
  } else if (IsDoubleElementsKind(elements_kind)) {
    float_value = TryTaggedToFloat64(value, bailout);
  }

  TNode<Smi> smi_length = Select<Smi>(
      IsJSArray(object),
      [=, this]() {
        // This is casting Number -> Smi which may not actually be safe.
        return CAST(LoadJSArrayLength(CAST(object)));
      },
      [=, this]() { return LoadFixedArrayBaseLength(elements); });

  TNode<UintPtrT> length = Unsigned(PositiveSmiUntag(smi_length));
  if (StoreModeCanGrow(store_mode) &&
      !(IsSealedElementsKind(elements_kind) ||
        IsNonextensibleElementsKind(elements_kind))) {
    elements = CheckForCapacityGrow(object, elements, elements_kind, length,
                                    intptr_key, bailout);
  } else {
    GotoIfNot(UintPtrLessThan(Unsigned(intptr_key), length), bailout);
  }

  // Cannot store to a hole in holey sealed elements so bailout.
  if (elements_kind == HOLEY_SEALED_ELEMENTS ||
      elements_kind == HOLEY_NONEXTENSIBLE_ELEMENTS) {
    TNode<Object> target_value =
        LoadFixedArrayElement(CAST(elements), intptr_key);
    GotoIf(IsTheHole(target_value), bailout);
  }

  // If we didn't grow {elements}, it might still be COW, in which case we
  // copy it now.
  if (!(IsSmiOrObjectElementsKind(elements_kind) ||
        IsSealedElementsKind(elements_kind) ||
        IsNonextensibleElementsKind(elements_kind))) {
    CSA_DCHECK(this, Word32BinaryNot(IsFixedCOWArrayMap(LoadMap(elements))));
  } else if (StoreModeHandlesCOW(store_mode)) {
    elements = CopyElementsOnWrite(object, elements, elements_kind,
                                   Signed(length), bailout);
  }

  CSA_DCHECK(this, Word32BinaryNot(IsFixedCOWArrayMap(LoadMap(elements))));
  if (float_value) {
    StoreElement(elements, elements_kind, intptr_key, float_value.value());
  } else {
    if (elements_kind == SHARED_ARRAY_ELEMENTS) {
      TVARIABLE(Object, shared_value, value);
      SharedValueBarrier(context, &shared_value);
      StoreElement(elements, elements_kind, intptr_key, shared_value.value());
    } else {
      StoreElement(elements, elements_kind, intptr_key, value);
    }
  }
}

TNode<FixedArrayBase> CodeStubAssembler::CheckForCapacityGrow(
    TNode<JSObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<UintPtrT> length, TNode<IntPtrT> key, Label* bailout) {
  DCHECK(IsFastElementsKind(kind));
  TVARIABLE(FixedArrayBase, checked_elements);
  Label grow_case(this), no_grow_case(this), done(this),
      grow_bailout(this, Label::kDeferred);

  TNode<BoolT> condition;
  if (IsHoleyElementsKind(kind)) {
    condition = UintPtrGreaterThanOrEqual(key, length);
  } else {
    // We don't support growing here unless the value is being appended.
    condition = WordEqual(key, length);
  }
  Branch(condition, &grow_case, &no_grow_case);

  BIND(&grow_case);
  {
    TNode<IntPtrT> current_capacity =
        LoadAndUntagFixedArrayBaseLength(elements);
    checked_elements = elements;
    Label fits_capacity(this);
    // If key is negative, we will notice in Runtime::kGrowArrayElements.
    GotoIf(UintPtrLessThan(key, current_capacity), &fits_capacity);

    {
      TNode<FixedArrayBase> new_elements = TryGrowElementsCapacity(
          object, elements, kind, key, current_capacity, &grow_bailout);
      checked_elements = new_elements;
      Goto(&fits_capacity);
    }

    BIND(&grow_bailout);
    {
      GotoIf(IntPtrLessThan(key, IntPtrConstant(0)), bailout);
      TNode<Number> tagged_key = ChangeUintPtrToTagged(Unsigned(key));
      TNode<Object> maybe_elements = CallRuntime(
          Runtime::kGrowArrayElements, NoContextConstant(), object, tagged_key);
      GotoIf(TaggedIsSmi(maybe_elements), bailout);
      TNode<FixedArrayBase> new_elements = CAST(maybe_elements);
      CSA_DCHECK(this, IsFixedArrayWithKind(new_elements, kind));
      checked_elements = new_elements;
      Goto(&fits_capacity);
    }

    BIND(&fits_capacity);
    GotoIfNot(IsJSArray(object), &done);

    TNode<IntPtrT> new_length = IntPtrAdd(key, IntPtrConstant(1));
    StoreObjectFieldNoWriteBarrier(object, JSArray::kLengthOffset,
                                   SmiTag(new_length));
    Goto(&done);
  }

  BIND(&no_grow_case);
  {
    GotoIfNot(UintPtrLessThan(key, length), bailout);
    checked_elements = elements;
    Goto(&done);
  }

  BIND(&done);
  return checked_elements.value();
}

TNode<FixedArrayBase> CodeStubAssembler::CopyElementsOnWrite(
    TNode<HeapObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
    TNode<IntPtrT> length, Label* bailout) {
  TVARIABLE(FixedArrayBase, new_elements_var, elements);
  Label done(this);

  GotoIfNot(IsFixedCOWArrayMap(LoadMap(elements)), &done);
  {
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    TNode<FixedArrayBase> new_elements = GrowElementsCapacity(
        object, elements, kind, kind, length, capacity, bailout);
    new_elements_var = new_elements;
    Goto(&done);
  }

  BIND(&done);
  return new_elements_var.value();
}

void CodeStubAssembler::TransitionElementsKind(TNode<JSObject> object,
                                               TNode<Map> map,
                                               ElementsKind from_kind,
```