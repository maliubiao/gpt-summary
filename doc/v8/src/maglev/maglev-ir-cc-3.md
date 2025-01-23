Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code seems to define various operations related to data manipulation and checks within the V8 JavaScript engine's Maglev compiler.

Here's a breakdown of how to approach this:

1. **Identify Code Blocks:**  Group the code based on the class names. Each class likely represents a specific operation or check.
2. **Analyze Class Names:**  The names often hint at the operation's purpose (e.g., `LoadHoleyFixedDoubleArrayElementCheckedNotHole`, `StoreMap`, `CheckSmi`).
3. **Examine `GenerateCode`:** This method contains the core logic for each operation, showing how it's implemented using assembly instructions (like `__ LoadFixedDoubleArrayElement`, `__ StoreTaggedFieldWithWriteBarrier`, `__ CompareTaggedAndJumpIf`).
4. **Look at `SetValueLocationConstraints`:** This method indicates how operands are handled (registers, fixed locations, etc.).
5. **Infer Functionality:** Based on the class name and the operations in `GenerateCode`, deduce what the code does.
6. **Relate to JavaScript (if applicable):**  Think about how these low-level operations translate to JavaScript concepts (e.g., accessing array elements, setting object properties, type checks).
7. **Create JavaScript Examples:** If a connection to JavaScript exists, provide a simple code snippet that would trigger the described operation.
8. **Infer Logic and Provide Examples:** For operations involving comparisons or conditions, provide hypothetical inputs and outputs.
9. **Identify Common Errors:** Consider potential programming mistakes that could lead to these operations being executed or their checks failing.
10. **Synthesize the Summary:** Combine the findings into a concise description of the file's functionality.

**Specific Code Block Analysis:**

* **Array Operations (`LoadHoleyFixedDoubleArrayElementCheckedNotHole`, `StoreFixedDoubleArrayElement`):**  These deal with accessing and modifying elements in double-precision floating-point arrays.
* **Object Property Operations (`StoreMap`, `StoreTaggedFieldWithWriteBarrier`, `StoreTrustedPointerFieldWithWriteBarrier`):**  These are responsible for setting object properties, including handling write barriers for garbage collection.
* **DataView Operations (`LoadSignedIntDataViewElement`, `StoreSignedIntDataViewElement`, `LoadDoubleDataViewElement`, `StoreDoubleDataViewElement`):** These handle reading and writing data to `DataView` objects, considering endianness.
* **Polymorphic Access (`EmitPolymorphicAccesses`):** This section deals with optimizing access to object properties when the object's type isn't known statically.
* **Global Variable Operations (`LoadGlobal`, `StoreGlobal`):**  These handle reading and writing global variables.
* **Value Checks (`CheckValue`, `CheckValueEqualsInt32`, `CheckValueEqualsFloat64`, `CheckFloat64IsNan`, `CheckValueEqualsString`, `CheckDynamicValue`):** These perform various comparisons between values.
* **Type Checks (`CheckSmi`, `CheckHeapObject`, `CheckSymbol`, `CheckInstanceType`):** These verify the type of a JavaScript value.
* **Array Bounds and Cache Checks (`CheckTypedArrayBounds`, `CheckCacheIndicesNotCleared`):** These ensure that array accesses are within bounds and that enum caches are valid.
* **Conditional Checks (`CheckInt32Condition`):** This performs a conditional jump based on an integer comparison.
* **Context Slot Operations (`StoreScriptContextSlotWithWriteBarrier`):** This handles storing values in script context slots, considering immutability and write barriers.
* **String Checks (`CheckString`):** This verifies if a value is a string.

By going through each of these blocks, we can build a comprehensive understanding of the code's function.
Based on the provided C++ code snippet from `v8/src/maglev/maglev-ir.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code defines various **intermediate representation (IR) nodes** used in the Maglev compiler pipeline within V8. These nodes represent specific operations that can be performed during the execution of JavaScript code. The `GenerateCode` methods within each node class are responsible for emitting the corresponding machine code (assembly instructions) for that operation.

**Key Areas Covered:**

* **Array Access:**
    * **`LoadHoleyFixedDoubleArrayElementCheckedNotHole`:** Loads an element from a `FixedDoubleArray`, specifically checking that the element is not a "hole" (an uninitialized value).
    * **`StoreFixedDoubleArrayElement`:** Stores a double-precision floating-point value into a `FixedDoubleArray`.

* **Object Property Access (including write barriers for garbage collection):**
    * **`StoreMap`:** Stores the map (object type information) of an object. It handles write barriers to ensure garbage collection is aware of the change.
    * **`StoreTaggedFieldWithWriteBarrier`:** Stores a tagged value (a value that can be a Smi or a pointer to a HeapObject) into a field of an object, including a write barrier.
    * **`StoreTrustedPointerFieldWithWriteBarrier`:**  Similar to `StoreTaggedFieldWithWriteBarrier` but specifically for storing "trusted pointers" (likely used in sandboxed environments).

* **DataView Operations (for typed arrays):**
    * **`LoadSignedIntDataViewElement`:** Loads a signed integer value from a `DataView`, handling endianness.
    * **`StoreSignedIntDataViewElement`:** Stores a signed integer value into a `DataView`, handling endianness.
    * **`LoadDoubleDataViewElement`:** Loads a double-precision floating-point value from a `DataView`, handling endianness.
    * **`StoreDoubleDataViewElement`:** Stores a double-precision floating-point value into a `DataView`, handling endianness.

* **Optimized Property Access (Polymorphic Access):**
    * **`EmitPolymorphicAccesses`:**  Handles property accesses on objects where the exact type might vary. It checks against a set of known object maps and executes specific code based on the map.

* **Global Variable Access:**
    * **`LoadGlobal`:** Loads the value of a global variable. It uses inline caching (IC) mechanisms for optimization.
    * **`StoreGlobal`:** Stores a value into a global variable, also using inline caching.

* **Value and Type Checks:**
    * **`CheckValue`:** Checks if a value is strictly equal to a constant value.
    * **`CheckValueEqualsInt32`:** Checks if a value is strictly equal to a given 32-bit integer.
    * **`CheckValueEqualsFloat64`:** Checks if a value is strictly equal to a given 64-bit floating-point number.
    * **`CheckFloat64IsNan`:** Checks if a value is NaN (Not-a-Number).
    * **`CheckValueEqualsString`:** Checks if a value is strictly equal to a given string. It might involve calling a builtin function for more complex string comparisons.
    * **`CheckDynamicValue`:** Checks if two dynamically determined values are strictly equal.
    * **`CheckSmi`:** Checks if a value is a Small Integer (Smi).
    * **`CheckHeapObject`:** Checks if a value is a HeapObject (not a Smi).
    * **`CheckSymbol`:** Checks if a value is a Symbol.
    * **`CheckInstanceType`:** Checks if an object's type matches a specific instance type or a range of instance types.
    * **`CheckCacheIndicesNotCleared`:** Checks if the indices in an enum cache have not been cleared.
    * **`CheckTypedArrayBounds`:** Checks if an index is within the bounds of a Typed Array.
    * **`CheckInt32Condition`:** Performs a conditional check based on an integer comparison.

* **Context Management:**
    * **`StoreScriptContextSlotWithWriteBarrier`:** Stores a value into a specific slot within a Script Context, including a write barrier.

* **Other Operations:**
    * **`LoadEnumCacheLength`:** Loads the length of an enumeration cache.

**Relation to JavaScript and Examples:**

Many of these operations directly correspond to actions performed in JavaScript:

* **Array Access:**
   ```javascript
   const arr = [1.1, 2.2];
   const value = arr[0]; // Corresponds to LoadHoleyFixedDoubleArrayElementCheckedNotHole
   arr[1] = 3.3;        // Corresponds to StoreFixedDoubleArrayElement
   ```

* **Object Property Access:**
   ```javascript
   const obj = { x: 10 };
   obj.y = 20; // Corresponds to StoreTaggedFieldWithWriteBarrier
   ```

* **DataView Operations:**
   ```javascript
   const buffer = new ArrayBuffer(8);
   const view = new DataView(buffer);
   view.setInt32(0, 12345, true); // StoreSignedIntDataViewElement (little-endian)
   const readValue = view.getInt32(0, true); // LoadSignedIntDataViewElement (little-endian)
   ```

* **Global Variable Access:**
   ```javascript
   let globalVar = 5;
   console.log(globalVar); // LoadGlobal
   globalVar = 10;         // StoreGlobal
   ```

* **Value and Type Checks:**
   ```javascript
   const x = 5;
   if (x === 5) { /* CheckValueEqualsInt32 */ }
   if (typeof x === 'number') { /* Implicit type check */ }
   if (Array.isArray(arr)) { /* CheckInstanceType */ }
   ```

**Code Logic Inference and Examples:**

Let's take `CheckValueEqualsInt32` as an example:

* **Assumption:** The input `target_input()` holds a JavaScript value that is expected to be the integer `value()`.
* **Input:** `target_input()` could be a register containing the result of a previous operation, and `value()` is a constant integer.
* **Output:** If the value in the register matches the constant integer, the code proceeds. If they are not equal, the code jumps to a deoptimization label (`fail`).

**Example in assembly (conceptual):**

```assembly
  // Assuming target_input() is in register R1, and value() is 10
  CMP R1, #10   // Compare the value in R1 with 10
  JNE fail_label // Jump to fail_label if not equal
  // ... continue if equal ...
fail_label:
  // ... deoptimization logic ...
```

**Common Programming Errors:**

* **Incorrect Data Types:**  Trying to store a value of the wrong type into an array or object property.
   ```javascript
   const arr = [1.1];
   arr[0] = "hello"; // This might lead to deoptimization or type errors later on if not handled correctly.
   ```
* **Out-of-Bounds Access:** Accessing array elements outside their valid range.
   ```javascript
   const arr = [1, 2];
   console.log(arr[2]); // This could trigger a `CheckTypedArrayBounds` failure.
   ```
* **Type Mismatches in Comparisons:**  Using strict equality (`===`) when the types are different and not handled by the compiler's optimizations.
   ```javascript
   const a = 5;
   const b = "5";
   if (a === b) { // CheckValue will likely fail here
       // ...
   }
   ```
* **Modifying Immutable Values:** Attempting to change constant or read-only properties. This relates to the checks in `StoreScriptContextSlotWithWriteBarrier`.

**Summary of Functionality (as requested in Part 4):**

This part of the `maglev-ir.cc` file defines a collection of **low-level operations** that the Maglev compiler uses to represent and execute JavaScript code. These operations cover fundamental actions like **accessing array elements, manipulating object properties, handling typed arrays, performing type and value checks, and managing execution context**. The code provides the blueprint for how these high-level JavaScript concepts are translated into efficient machine code, including considerations for garbage collection and optimization techniques like inline caching.

### 提示词
```
这是目录为v8/src/maglev/maglev-ir.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-ir.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
efineAsRegister(this);
  set_temporaries_needed(1);
}
void LoadHoleyFixedDoubleArrayElementCheckedNotHole::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  DoubleRegister result_reg = ToDoubleRegister(result());
  __ LoadFixedDoubleArrayElement(result_reg, elements, index);
  __ JumpIfHoleNan(result_reg, temps.Acquire(),
                   __ GetDeoptLabel(this, DeoptimizeReason::kHole));
}

void StoreFixedDoubleArrayElement::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  UseRegister(value_input());
}
void StoreFixedDoubleArrayElement::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  DoubleRegister value = ToDoubleRegister(value_input());
  if (v8_flags.debug_code) {
    __ AssertObjectType(elements, FIXED_DOUBLE_ARRAY_TYPE,
                        AbortReason::kUnexpectedValue);
    __ CompareInt32AndAssert(index, 0, kUnsignedGreaterThanEqual,
                             AbortReason::kUnexpectedNegativeValue);
  }
  __ StoreFixedDoubleArrayElement(elements, index, value);
}

int StoreMap::MaxCallStackArgs() const {
  return WriteBarrierDescriptor::GetStackParameterCount();
}
void StoreMap::SetValueLocationConstraints() {
  UseFixed(object_input(), WriteBarrierDescriptor::ObjectRegister());
  set_temporaries_needed(1);
}
void StoreMap::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  // TODO(leszeks): Consider making this an arbitrary register and push/popping
  // in the deferred path.
  Register object = WriteBarrierDescriptor::ObjectRegister();
  DCHECK_EQ(object, ToRegister(object_input()));
  Register value = temps.Acquire();
  __ MoveTagged(value, map_.object());

  if (kind() == Kind::kInitializingYoung) {
    __ StoreTaggedFieldNoWriteBarrier(object, HeapObject::kMapOffset, value);
  } else {
    __ StoreTaggedFieldWithWriteBarrier(object, HeapObject::kMapOffset, value,
                                        register_snapshot(),
                                        MaglevAssembler::kValueIsCompressed,
                                        MaglevAssembler::kValueCannotBeSmi);
  }
}

int StoreTaggedFieldWithWriteBarrier::MaxCallStackArgs() const {
  return WriteBarrierDescriptor::GetStackParameterCount();
}
void StoreTaggedFieldWithWriteBarrier::SetValueLocationConstraints() {
  UseFixed(object_input(), WriteBarrierDescriptor::ObjectRegister());
  UseRegister(value_input());
}
void StoreTaggedFieldWithWriteBarrier::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  // TODO(leszeks): Consider making this an arbitrary register and push/popping
  // in the deferred path.
  Register object = WriteBarrierDescriptor::ObjectRegister();
  DCHECK_EQ(object, ToRegister(object_input()));
  Register value = ToRegister(value_input());

  __ StoreTaggedFieldWithWriteBarrier(
      object, offset(), value, register_snapshot(),
      value_input().node()->decompresses_tagged_result()
          ? MaglevAssembler::kValueIsDecompressed
          : MaglevAssembler::kValueIsCompressed,
      MaglevAssembler::kValueCanBeSmi);
}

int StoreTrustedPointerFieldWithWriteBarrier::MaxCallStackArgs() const {
  return WriteBarrierDescriptor::GetStackParameterCount();
}
void StoreTrustedPointerFieldWithWriteBarrier::SetValueLocationConstraints() {
  UseFixed(object_input(), WriteBarrierDescriptor::ObjectRegister());
  UseRegister(value_input());
}
void StoreTrustedPointerFieldWithWriteBarrier::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
#ifdef V8_ENABLE_SANDBOX
  // TODO(leszeks): Consider making this an arbitrary register and push/popping
  // in the deferred path.
  Register object = WriteBarrierDescriptor::ObjectRegister();
  DCHECK_EQ(object, ToRegister(object_input()));
  Register value = ToRegister(value_input());
  __ StoreTrustedPointerFieldWithWriteBarrier(object, offset(), value,
                                              register_snapshot(), tag());
#else
  UNREACHABLE();
#endif
}

void LoadSignedIntDataViewElement::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(index_input());
  if (is_little_endian_constant() ||
      type_ == ExternalArrayType::kExternalInt8Array) {
    UseAny(is_little_endian_input());
  } else {
    UseRegister(is_little_endian_input());
  }
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void LoadSignedIntDataViewElement::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register index = ToRegister(index_input());
  Register result_reg = ToRegister(result());

  if (v8_flags.debug_code) {
    __ AssertObjectTypeInRange(object,
                               FIRST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               LAST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               AbortReason::kUnexpectedValue);
  }

  int element_size = compiler::ExternalArrayElementSize(type_);

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register data_pointer = temps.Acquire();

  // We need to make sure we don't clobber is_little_endian_input by writing to
  // the result register.
  Register reg_with_result = result_reg;
  if (type_ != ExternalArrayType::kExternalInt8Array &&
      !is_little_endian_constant() &&
      result_reg == ToRegister(is_little_endian_input())) {
    reg_with_result = data_pointer;
  }

  // Load data pointer.
  __ LoadExternalPointerField(
      data_pointer, FieldMemOperand(object, JSDataView::kDataPointerOffset));
  MemOperand element_address = __ DataViewElementOperand(data_pointer, index);
  __ LoadSignedField(reg_with_result, element_address, element_size);

  // We ignore little endian argument if type is a byte size.
  if (type_ != ExternalArrayType::kExternalInt8Array) {
    if (is_little_endian_constant()) {
      if (!V8_TARGET_BIG_ENDIAN_BOOL &&
          !FromConstantToBool(masm, is_little_endian_input().node())) {
        DCHECK_EQ(reg_with_result, result_reg);
        __ ReverseByteOrder(result_reg, element_size);
      }
    } else {
      ZoneLabelRef keep_byte_order(masm), reverse_byte_order(masm);
      DCHECK_NE(reg_with_result, ToRegister(is_little_endian_input()));
      __ ToBoolean(
          ToRegister(is_little_endian_input()), CheckType::kCheckHeapObject,
          V8_TARGET_BIG_ENDIAN_BOOL ? reverse_byte_order : keep_byte_order,
          V8_TARGET_BIG_ENDIAN_BOOL ? keep_byte_order : reverse_byte_order,
          false);
      __ bind(*reverse_byte_order);
      __ ReverseByteOrder(reg_with_result, element_size);
      __ bind(*keep_byte_order);
      if (reg_with_result != result_reg) {
        __ Move(result_reg, reg_with_result);
      }
    }
  }
}

void StoreSignedIntDataViewElement::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(index_input());
  if (compiler::ExternalArrayElementSize(type_) > 1) {
    UseAndClobberRegister(value_input());
  } else {
    UseRegister(value_input());
  }
  if (is_little_endian_constant() ||
      type_ == ExternalArrayType::kExternalInt8Array) {
    UseAny(is_little_endian_input());
  } else {
    UseRegister(is_little_endian_input());
  }
  set_temporaries_needed(1);
}
void StoreSignedIntDataViewElement::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register index = ToRegister(index_input());
  Register value = ToRegister(value_input());

  if (v8_flags.debug_code) {
    __ AssertObjectTypeInRange(object,
                               FIRST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               LAST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               AbortReason::kUnexpectedValue);
  }

  int element_size = compiler::ExternalArrayElementSize(type_);

  // We ignore little endian argument if type is a byte size.
  if (element_size > 1) {
    if (is_little_endian_constant()) {
      if (!V8_TARGET_BIG_ENDIAN_BOOL &&
          !FromConstantToBool(masm, is_little_endian_input().node())) {
        __ ReverseByteOrder(value, element_size);
      }
    } else {
      ZoneLabelRef keep_byte_order(masm), reverse_byte_order(masm);
      __ ToBoolean(
          ToRegister(is_little_endian_input()), CheckType::kCheckHeapObject,
          V8_TARGET_BIG_ENDIAN_BOOL ? reverse_byte_order : keep_byte_order,
          V8_TARGET_BIG_ENDIAN_BOOL ? keep_byte_order : reverse_byte_order,
          false);
      __ bind(*reverse_byte_order);
      __ ReverseByteOrder(value, element_size);
      __ bind(*keep_byte_order);
    }
  }

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register data_pointer = temps.Acquire();
  __ LoadExternalPointerField(
      data_pointer, FieldMemOperand(object, JSDataView::kDataPointerOffset));
  MemOperand element_address = __ DataViewElementOperand(data_pointer, index);
  __ StoreField(element_address, value, element_size);
}

void LoadDoubleDataViewElement::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(index_input());
  if (is_little_endian_constant()) {
    UseAny(is_little_endian_input());
  } else {
    UseRegister(is_little_endian_input());
  }
  set_temporaries_needed(1);
  DefineAsRegister(this);
}
void LoadDoubleDataViewElement::GenerateCode(MaglevAssembler* masm,
                                             const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(object_input());
  Register index = ToRegister(index_input());
  DoubleRegister result_reg = ToDoubleRegister(result());
  Register data_pointer = temps.Acquire();

  if (v8_flags.debug_code) {
    __ AssertObjectTypeInRange(object,
                               FIRST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               LAST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               AbortReason::kUnexpectedValue);
  }

  // Load data pointer.
  __ LoadExternalPointerField(
      data_pointer, FieldMemOperand(object, JSDataView::kDataPointerOffset));

  if (is_little_endian_constant()) {
    if (!V8_TARGET_BIG_ENDIAN_BOOL &&
        FromConstantToBool(masm, is_little_endian_input().node())) {
      __ LoadUnalignedFloat64(result_reg, data_pointer, index);
    } else {
      __ LoadUnalignedFloat64AndReverseByteOrder(result_reg, data_pointer,
                                                 index);
    }
  } else {
    Label done;
    ZoneLabelRef keep_byte_order(masm), reverse_byte_order(masm);
    // TODO(leszeks): We're likely to be calling this on an existing boolean --
    // maybe that's a case we should fast-path here and re-use that boolean
    // value?
    __ ToBoolean(
        ToRegister(is_little_endian_input()), CheckType::kCheckHeapObject,
        V8_TARGET_BIG_ENDIAN_BOOL ? reverse_byte_order : keep_byte_order,
        V8_TARGET_BIG_ENDIAN_BOOL ? keep_byte_order : reverse_byte_order, true);
    __ bind(*keep_byte_order);
    __ LoadUnalignedFloat64(result_reg, data_pointer, index);
    __ Jump(&done);
    // We should swap the bytes if big endian.
    __ bind(*reverse_byte_order);
    __ LoadUnalignedFloat64AndReverseByteOrder(result_reg, data_pointer, index);
    __ bind(&done);
  }
}

void StoreDoubleDataViewElement::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(index_input());
  UseRegister(value_input());
  if (is_little_endian_constant()) {
    UseAny(is_little_endian_input());
  } else {
    UseRegister(is_little_endian_input());
  }
  set_temporaries_needed(1);
}
void StoreDoubleDataViewElement::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register index = ToRegister(index_input());
  DoubleRegister value = ToDoubleRegister(value_input());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register data_pointer = temps.Acquire();

  if (v8_flags.debug_code) {
    __ AssertObjectTypeInRange(object,
                               FIRST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               LAST_JS_DATA_VIEW_OR_RAB_GSAB_DATA_VIEW_TYPE,
                               AbortReason::kUnexpectedValue);
  }

  // Load data pointer.
  __ LoadExternalPointerField(
      data_pointer, FieldMemOperand(object, JSDataView::kDataPointerOffset));

  if (is_little_endian_constant()) {
    if (!V8_TARGET_BIG_ENDIAN_BOOL &&
        FromConstantToBool(masm, is_little_endian_input().node())) {
      __ StoreUnalignedFloat64(data_pointer, index, value);
    } else {
      __ ReverseByteOrderAndStoreUnalignedFloat64(data_pointer, index, value);
    }
  } else {
    Label done;
    ZoneLabelRef keep_byte_order(masm), reverse_byte_order(masm);
    // TODO(leszeks): We're likely to be calling this on an existing boolean --
    // maybe that's a case we should fast-path here and re-use that boolean
    // value?
    __ ToBoolean(
        ToRegister(is_little_endian_input()), CheckType::kCheckHeapObject,
        V8_TARGET_BIG_ENDIAN_BOOL ? reverse_byte_order : keep_byte_order,
        V8_TARGET_BIG_ENDIAN_BOOL ? keep_byte_order : reverse_byte_order, true);
    __ bind(*keep_byte_order);
    __ StoreUnalignedFloat64(data_pointer, index, value);
    __ Jump(&done);
    // We should swap the bytes if big endian.
    __ bind(*reverse_byte_order);
    __ ReverseByteOrderAndStoreUnalignedFloat64(data_pointer, index, value);
    __ bind(&done);
  }
}

namespace {

template <typename NodeT, typename Function, typename... Args>
void EmitPolymorphicAccesses(MaglevAssembler* masm, NodeT* node,
                             Register object, Function&& f, Args&&... args) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object_map = temps.Acquire();
  Label done;
  Label is_number;
  Label* deopt = __ GetDeoptLabel(node, DeoptimizeReason::kWrongMap);

  __ JumpIfSmi(object, &is_number);
  __ LoadMap(object_map, object);

  for (const PolymorphicAccessInfo& access_info : node->access_infos()) {
    Label next;
    Label map_found;
    auto& maps = access_info.maps();

    bool has_number_map = false;
    if (HasOnlyStringMaps(base::VectorOf(maps))) {
      __ JumpIfStringMap(object_map, &next, Label::kFar, false);
      // Fallthrough... to map_found.
    } else {
      for (auto it = maps.begin(); it != maps.end(); ++it) {
        if (IsHeapNumberMap(*it->object())) {
          if (it == maps.end() - 1) {
            __ JumpIfNotRoot(object_map, RootIndex::kHeapNumberMap, &next);
          } else {
            __ JumpIfRoot(object_map, RootIndex::kHeapNumberMap, &map_found);
          }
          has_number_map = true;
        } else {
          if (it == maps.end() - 1) {
            __ CompareTaggedAndJumpIf(object_map, it->object(), kNotEqual,
                                      &next);
            // Fallthrough... to map_found.
          } else {
            __ CompareTaggedAndJumpIf(object_map, it->object(), kEqual,
                                      &map_found);
          }
        }
      }
    }

    if (has_number_map) {
      DCHECK(!is_number.is_bound());
      __ bind(&is_number);
    }
    __ bind(&map_found);
    __ EmitEagerDeoptStress(deopt);
    f(masm, node, access_info, object, object_map, std::forward<Args>(args)...);
    __ Jump(&done);

    __ bind(&next);
  }

  // A HeapNumberMap was not found, we should eager deopt here in case of a
  // number.
  if (!is_number.is_bound()) {
    __ bind(&is_number);
  }

  // No map matched!
  __ JumpToDeopt(deopt);
  __ bind(&done);
}

}  // namespace

void LoadEnumCacheLength::SetValueLocationConstraints() {
  UseRegister(map_input());
  DefineAsRegister(this);
}
void LoadEnumCacheLength::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Register map = ToRegister(map_input());
  Register result_reg = ToRegister(result());
  __ AssertMap(map);
  __ LoadBitField<Map::Bits3::EnumLengthBits>(
      result_reg, FieldMemOperand(map, Map::kBitField3Offset));
}

int LoadGlobal::MaxCallStackArgs() const {
  if (typeof_mode() == TypeofMode::kNotInside) {
    using D = CallInterfaceDescriptorFor<Builtin::kLoadGlobalIC>::type;
    return D::GetStackParameterCount();
  } else {
    using D =
        CallInterfaceDescriptorFor<Builtin::kLoadGlobalICInsideTypeof>::type;
    return D::GetStackParameterCount();
  }
}
void LoadGlobal::SetValueLocationConstraints() {
  UseFixed(context(), kContextRegister);
  DefineAsFixed(this, kReturnRegister0);
}
void LoadGlobal::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  if (typeof_mode() == TypeofMode::kNotInside) {
    __ CallBuiltin<Builtin::kLoadGlobalIC>(
        context(),                                    // context
        name().object(),                              // name
        TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
        feedback().vector                             // feedback vector
    );
  } else {
    DCHECK_EQ(typeof_mode(), TypeofMode::kInside);
    __ CallBuiltin<Builtin::kLoadGlobalICInsideTypeof>(
        context(),                                    // context
        name().object(),                              // name
        TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
        feedback().vector                             // feedback vector
    );
  }

  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int StoreGlobal::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kStoreGlobalIC>::type;
  return D::GetStackParameterCount();
}
void StoreGlobal::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kStoreGlobalIC>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(value(), D::GetRegisterParameter(D::kValue));
  DefineAsFixed(this, kReturnRegister0);
}
void StoreGlobal::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  __ CallBuiltin<Builtin::kStoreGlobalIC>(
      context(),                                    // context
      name().object(),                              // name
      value(),                                      // value
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void CheckValue::SetValueLocationConstraints() { UseRegister(target_input()); }
void CheckValue::GenerateCode(MaglevAssembler* masm,
                              const ProcessingState& state) {
  Register target = ToRegister(target_input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongValue);
  __ CompareTaggedAndJumpIf(target, value().object(), kNotEqual, fail);
}

void CheckValueEqualsInt32::SetValueLocationConstraints() {
  UseRegister(target_input());
}
void CheckValueEqualsInt32::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register target = ToRegister(target_input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongValue);
  __ CompareInt32AndJumpIf(target, value(), kNotEqual, fail);
}

void CheckValueEqualsFloat64::SetValueLocationConstraints() {
  UseRegister(target_input());
  set_double_temporaries_needed(1);
}
void CheckValueEqualsFloat64::GenerateCode(MaglevAssembler* masm,
                                           const ProcessingState& state) {
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongValue);
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  DoubleRegister scratch = temps.AcquireDouble();
  DoubleRegister target = ToDoubleRegister(target_input());
  __ Move(scratch, value());
  __ CompareFloat64AndJumpIf(scratch, target, kNotEqual, fail, fail);
}

void CheckFloat64IsNan::SetValueLocationConstraints() {
  UseRegister(target_input());
}
void CheckFloat64IsNan::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongValue);
  DoubleRegister target = ToDoubleRegister(target_input());
  __ JumpIfNotNan(target, fail);
}

void CheckValueEqualsString::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kStringEqual>::type;
  UseFixed(target_input(), D::GetRegisterParameter(D::kLeft));
  RequireSpecificTemporary(D::GetRegisterParameter(D::kLength));
}
void CheckValueEqualsString::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  using D = CallInterfaceDescriptorFor<Builtin::kStringEqual>::type;

  ZoneLabelRef end(masm);
  DCHECK_EQ(D::GetRegisterParameter(D::kLeft), ToRegister(target_input()));
  Register target = D::GetRegisterParameter(D::kLeft);
  // Maybe the string is internalized already, do a fast reference check first.
  __ CompareTaggedAndJumpIf(target, value().object(), kEqual, *end,
                            Label::kNear);

  __ EmitEagerDeoptIfSmi(this, target, DeoptimizeReason::kWrongValue);
  __ JumpIfString(
      target,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, CheckValueEqualsString* node,
             ZoneLabelRef end) {
            Register target = D::GetRegisterParameter(D::kLeft);
            Register string_length = D::GetRegisterParameter(D::kLength);
            __ StringLength(string_length, target);
            Label* fail = __ GetDeoptLabel(node, DeoptimizeReason::kWrongValue);
            __ CompareInt32AndJumpIf(string_length, node->value().length(),
                                     kNotEqual, fail);
            RegisterSnapshot snapshot = node->register_snapshot();
            {
              SaveRegisterStateForCall save_register_state(masm, snapshot);
              __ CallBuiltin<Builtin::kStringEqual>(
                  node->target_input(),    // left
                  node->value().object(),  // right
                  string_length            // length
              );
              save_register_state.DefineSafepoint();
              // Compare before restoring registers, so that the deopt below has
              // the correct register set.
              __ CompareRoot(kReturnRegister0, RootIndex::kTrueValue);
            }
            __ EmitEagerDeoptIf(kNotEqual, DeoptimizeReason::kWrongValue, node);
            __ Jump(*end);
          },
          this, end));

  __ EmitEagerDeopt(this, DeoptimizeReason::kWrongValue);

  __ bind(*end);
}

void CheckDynamicValue::SetValueLocationConstraints() {
  UseRegister(first_input());
  UseRegister(second_input());
}
void CheckDynamicValue::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Register first = ToRegister(first_input());
  Register second = ToRegister(second_input());
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongValue);
  __ CompareTaggedAndJumpIf(first, second, kNotEqual, fail);
}

void CheckSmi::SetValueLocationConstraints() { UseRegister(receiver_input()); }
void CheckSmi::GenerateCode(MaglevAssembler* masm,
                            const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  __ EmitEagerDeoptIfNotSmi(this, object, DeoptimizeReason::kNotASmi);
}

void CheckHeapObject::SetValueLocationConstraints() {
  UseRegister(receiver_input());
}
void CheckHeapObject::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kSmi);
}

void CheckSymbol::SetValueLocationConstraints() {
  UseRegister(receiver_input());
}
void CheckSymbol::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kNotASymbol);
  }
  __ JumpIfNotObjectType(object, SYMBOL_TYPE,
                         __ GetDeoptLabel(this, DeoptimizeReason::kNotASymbol));
}

void CheckInstanceType::SetValueLocationConstraints() {
  UseRegister(receiver_input());
}
void CheckInstanceType::GenerateCode(MaglevAssembler* masm,
                                     const ProcessingState& state) {
  Register object = ToRegister(receiver_input());
  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kWrongInstanceType);
  }
  if (first_instance_type_ == last_instance_type_) {
    __ JumpIfNotObjectType(
        object, first_instance_type_,
        __ GetDeoptLabel(this, DeoptimizeReason::kWrongInstanceType));
  } else {
    __ JumpIfObjectTypeNotInRange(
        object, first_instance_type_, last_instance_type_,
        __ GetDeoptLabel(this, DeoptimizeReason::kWrongInstanceType));
  }
}

void CheckCacheIndicesNotCleared::SetValueLocationConstraints() {
  UseRegister(indices_input());
  UseRegister(length_input());
}
void CheckCacheIndicesNotCleared::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
  Register indices = ToRegister(indices_input());
  Register length = ToRegister(length_input());
  __ AssertNotSmi(indices);

  if (v8_flags.debug_code) {
    __ AssertObjectType(indices, FIXED_ARRAY_TYPE,
                        AbortReason::kOperandIsNotAFixedArray);
  }
  Label done;
  // If the cache length is zero, we don't have any indices, so we know this is
  // ok even though the indices are the empty array.
  __ CompareInt32AndJumpIf(length, 0, kEqual, &done);
  // Otherwise, an empty array with non-zero required length is not valid.
  __ JumpIfRoot(indices, RootIndex::kEmptyFixedArray,
                __ GetDeoptLabel(this, DeoptimizeReason::kWrongEnumIndices));
  __ bind(&done);
}

void CheckTypedArrayBounds::SetValueLocationConstraints() {
  UseRegister(index_input());
  UseRegister(length_input());
}
void CheckTypedArrayBounds::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register index = ToRegister(index_input());
  Register length = ToRegister(length_input());
  // The index must be a zero-extended Uint32 for this to work.
#ifdef V8_TARGET_ARCH_RISCV64
  // All Word32 values are been signed-extended in Register in RISCV.
  __ ZeroExtendWord(index, index);
#endif
  __ AssertZeroExtended(index);
  __ CompareIntPtrAndJumpIf(
      index, length, kUnsignedGreaterThanEqual,
      __ GetDeoptLabel(this, DeoptimizeReason::kOutOfBounds));
}

void CheckInt32Condition::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
}
void CheckInt32Condition::GenerateCode(MaglevAssembler* masm,
                                       const ProcessingState& state) {
  Label* fail = __ GetDeoptLabel(this, reason());
  __ CompareInt32AndJumpIf(ToRegister(left_input()), ToRegister(right_input()),
                           NegateCondition(ToCondition(condition())), fail);
}

int StoreScriptContextSlotWithWriteBarrier::MaxCallStackArgs() const {
  return WriteBarrierDescriptor::GetStackParameterCount();
}

void StoreScriptContextSlotWithWriteBarrier::SetValueLocationConstraints() {
  UseFixed(context_input(), WriteBarrierDescriptor::ObjectRegister());
  UseRegister(new_value_input());
  set_temporaries_needed(2);
  set_double_temporaries_needed(1);
}

void StoreScriptContextSlotWithWriteBarrier::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  __ RecordComment("StoreScriptContextSlotWithWriteBarrier");
  ZoneLabelRef done(masm);
  ZoneLabelRef do_normal_store(masm);

  // TODO(leszeks): Consider making this an arbitrary register and push/popping
  // in the deferred path.
  Register context = WriteBarrierDescriptor::ObjectRegister();
  Register new_value = ToRegister(new_value_input());
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register scratch = temps.Acquire();
  Register old_value = temps.Acquire();

  __ AssertObjectType(context, SCRIPT_CONTEXT_TYPE,
                      AbortReason::kUnexpectedInstanceType);

  __ LoadTaggedField(old_value, context, offset());
  __ CompareTaggedAndJumpIf(old_value, new_value, kEqual, *done);

  // Load property.
  // TODO(victorgomes): Should we hoist the side_table?
  __ LoadTaggedField(
      scratch, context,
      Context::OffsetOfElementAt(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX));
  __ LoadTaggedField(scratch, scratch,
                     FixedArray::OffsetOfElementAt(
                         index() - Context::MIN_CONTEXT_EXTENDED_SLOTS));

  __ CompareTaggedAndJumpIf(
      scratch, ContextSidePropertyCell::Other(), kNotEqual,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, Register context, Register old_value,
             Register new_value, Register property,
             StoreScriptContextSlotWithWriteBarrier* node, ZoneLabelRef done,
             ZoneLabelRef do_normal_store) {
            Label check_smi;
            Label new_value_should_be_a_number;
            __ CompareRootAndEmitEagerDeoptIf(
                property, RootIndex::kUndefinedValue, kEqual,
                DeoptimizeReason::kWrongValue, node);
            __ JumpIfSmi(property, &check_smi);
            __ AssertObjectType(property, CONTEXT_SIDE_PROPERTY_CELL_TYPE,
                                AbortReason::kUnexpectedInstanceType);
            __ LoadTaggedField(
                property, property,
                ContextSidePropertyCell::kPropertyDetailsRawOffset);
            __ bind(&check_smi);

            // Check for const case.
            __ CompareTaggedAndJumpIf(
                property, ContextSidePropertyCell::Const(), kEqual,
                __ GetDeoptLabel(node, DeoptimizeReason::kWrongValue));

            if (v8_flags.script_context_mutable_heap_number) {
              // Check for smi case
              __ CompareTaggedAndJumpIf(
                  property, ContextSidePropertyCell::SmiMarker(), kNotEqual,
                  &new_value_should_be_a_number);
              __ EmitEagerDeoptIfNotSmi(node, new_value,
                                        DeoptimizeReason::kWrongValue);
              __ Jump(*do_normal_store);

              // Check mutable heap number case.
              MaglevAssembler::TemporaryRegisterScope temps(masm);
              DoubleRegister double_scratch = temps.AcquireDouble();
              __ bind(&new_value_should_be_a_number);
              Label new_value_is_not_smi;
              __ JumpIfNotSmi(new_value, &new_value_is_not_smi);
              Register new_value_int32 = property;
              __ SmiUntag(new_value_int32, new_value);
              __ Int32ToDouble(double_scratch, new_value_int32);
              __ StoreFloat64(
                  FieldMemOperand(old_value, offsetof(HeapNumber, value_)),
                  double_scratch);
              __ Jump(*done);

              __ bind(&new_value_is_not_smi);
              __ CompareMapWithRoot(new_value, RootIndex::kHeapNumberMap,
                                    property);
              __ EmitEagerDeoptIf(kNotEqual, DeoptimizeReason::kWrongValue,
                                  node);

              __ LoadHeapNumberValue(double_scratch, new_value);
              __ StoreFloat64(
                  FieldMemOperand(old_value, offsetof(HeapNumber, value_)),
                  double_scratch);
              __ Jump(*done);
            } else {
              __ Jump(*do_normal_store);
            }
          },
          context, old_value, new_value, scratch, this, done, do_normal_store));

  __ bind(*do_normal_store);
  __ StoreTaggedFieldWithWriteBarrier(
      context, offset(), new_value, register_snapshot(),
      new_value_input().node()->decompresses_tagged_result()
          ? MaglevAssembler::kValueIsDecompressed
          : MaglevAssembler::kValueIsCompressed,
      MaglevAssembler::kValueCanBeSmi);

  __ bind(*done);
}

void CheckString::SetValueLocationCons
```