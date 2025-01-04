Response: The user wants me to summarize the functionality of the C++ source code file `v8/src/maglev/maglev-ir.cc`. This is the second part of a five-part series, so I should focus on the code within this specific section. I also need to provide a JavaScript example if the code relates to JavaScript functionality.

Based on the provided code snippets, it appears this file defines various nodes (classes) that represent intermediate representation (IR) instructions for the Maglev compiler in V8. These nodes seem to handle operations like:

*   Type checking (`CheckMaps`, `CheckMapsWithMigration`, `CheckMapsWithAlreadyLoadedMap`, `CheckSmi`, `CheckHeapObject`, `CheckSymbol`, `CheckInstanceType`)
*   Property manipulation (`DeleteProperty`, `LoadTaggedField`, `LoadTaggedFieldByFieldIndex`, `StoreTaggedFieldWithWriteBarrier`, `StoreTrustedPointerFieldWithWriteBarrier`)
*   Iteration (`ForInPrepare`, `ForInNext`, `GetIterator`)
*   Comparisons (`Int32Compare`, `Float64Compare`)
*   Conversions (`Int32ToBoolean`, `Float64ToBoolean`, `CheckedHoleyFloat64ToFloat64`)
*   DataView operations (`LoadSignedIntDataViewElement`, `StoreSignedIntDataViewElement`, `LoadDoubleDataViewElement`, `StoreDoubleDataViewElement`)
*   Global variable access (`LoadGlobal`, `StoreGlobal`)
*   Value checking (`CheckValue`, `CheckValueEqualsInt32`, `CheckValueEqualsFloat64`, `CheckFloat64IsNan`, `CheckValueEqualsString`, `CheckDynamicValue`)
*   Array operations (`LoadFixedArrayElement`, `LoadFixedDoubleArrayElement`, `LoadHoleyFixedDoubleArrayElement`, `LoadHoleyFixedDoubleArrayElementCheckedNotHole`, `StoreFixedDoubleArrayElement`)
*   Map manipulation (`StoreMap`, `MigrateMapIfNeeded`)
*   Enum cache loading (`LoadEnumCacheLength`)
*   Context slot operations (`StoreScriptContextSlotWithWriteBarrier`, `LoadTaggedFieldForScriptContextSlot`)
*   Typed array bounds checking (`CheckTypedArrayBounds`)
*   Conditional checks (`CheckInt32Condition`)
*   String checking (`CheckString`)

Many of these operations have a direct correspondence to JavaScript functionalities. I will select a few representative examples for the JavaScript illustration.This C++ code file, `maglev-ir.cc`, defines a variety of **intermediate representation (IR) nodes** used within the Maglev compiler pipeline of the V8 JavaScript engine. These nodes represent individual operations or checks that need to be performed during the compilation and execution of JavaScript code.

Here's a breakdown of the functionality represented by the code snippets in this section:

*   **Type Checking:**  Nodes like `CheckMaps`, `CheckMapsWithMigration`, `CheckMapsWithAlreadyLoadedMap`, `CheckSmi`, `CheckHeapObject`, `CheckSymbol`, and `CheckInstanceType` are responsible for verifying the type of JavaScript values at runtime. These checks ensure that operations are performed on objects of the expected types, and they can trigger deoptimization if the type assumption is violated. `CheckMapsWithMigration` specifically handles cases where an object's map might have changed due to object migration.
*   **Property Access and Manipulation:** Nodes like `DeleteProperty`, `LoadTaggedField`, `LoadTaggedFieldByFieldIndex`, `StoreTaggedFieldWithWriteBarrier`, and `StoreTrustedPointerFieldWithWriteBarrier` deal with accessing and modifying object properties. They handle different scenarios, including loading fields at known offsets, loading based on dynamic field indices, and ensuring proper write barriers for garbage collection.
*   **Iteration:** Nodes like `ForInPrepare`, `ForInNext`, and `GetIterator` support the implementation of JavaScript's `for...in` loops and iterator protocols.
*   **Comparisons:** Nodes like `Int32Compare` and `Float64Compare` perform numerical comparisons and produce boolean results.
*   **Type Conversions:** Nodes like `Int32ToBoolean`, `Float64ToBoolean`, and `CheckedHoleyFloat64ToFloat64` handle conversions between different JavaScript types.
*   **DataView Operations:** Nodes like `LoadSignedIntDataViewElement`, `StoreSignedIntDataViewElement`, `LoadDoubleDataViewElement`, and `StoreDoubleDataViewElement` are responsible for reading and writing elements of `DataView` objects, which provide a way to access raw binary data. They handle byte ordering (endianness).
*   **Global Variable Access:** Nodes like `LoadGlobal` and `StoreGlobal` handle the access and modification of global JavaScript variables. They utilize inline caching (IC) for optimization.
*   **Value Checks:** Nodes like `CheckValue`, `CheckValueEqualsInt32`, `CheckValueEqualsFloat64`, `CheckFloat64IsNan`, `CheckValueEqualsString`, and `CheckDynamicValue` perform direct value comparisons.
*   **Array Operations:** Nodes like `LoadFixedArrayElement`, `LoadFixedDoubleArrayElement`, `LoadHoleyFixedDoubleArrayElement`, `LoadHoleyFixedDoubleArrayElementCheckedNotHole`, and `StoreFixedDoubleArrayElement` deal with accessing and modifying elements of various types of JavaScript arrays.
*   **Map Manipulation:** Nodes like `StoreMap` and `MigrateMapIfNeeded` deal with setting object maps and handling object migration scenarios where the map might need to be updated.
*   **Enum Cache Loading:** `LoadEnumCacheLength` is used to retrieve the length of an enumeration cache.
*   **Context Slot Operations:** `StoreScriptContextSlotWithWriteBarrier` and `LoadTaggedFieldForScriptContextSlot` handle accessing and modifying variables stored in the JavaScript context (scope).
*   **Typed Array Bounds Checking:** `CheckTypedArrayBounds` ensures that accesses to Typed Arrays are within their valid bounds.
*   **Conditional Checks:** `CheckInt32Condition` performs integer comparisons and triggers deoptimization if a condition is not met.
*   **String Checks:** `CheckString` verifies that a value is a string.

**Relationship to JavaScript and Examples:**

Many of these IR nodes directly correspond to common JavaScript operations. Here are a few examples:

**1. `CheckMaps` (Type Checking):**

This node ensures that an object has one of a specific set of Maps (which define the object's structure and type).

```javascript
function processObject(obj) {
  // The Maglev compiler might insert a CheckMaps node here
  // to ensure 'obj' is an object with the expected structure.
  if (typeof obj.name === 'string') {
    console.log(obj.name.toUpperCase());
  }
}

processObject({ name: 'example' }); // This would likely pass the CheckMaps.
processObject(123);                 // This would likely fail the CheckMaps and potentially deoptimize.
```

**2. `LoadTaggedField` (Property Access):**

This node represents loading a property from an object at a specific memory offset.

```javascript
const myObject = { x: 10 };
// Accessing myObject.x might translate to a LoadTaggedField operation.
console.log(myObject.x);
```

**3. `Int32Compare` (Comparison):**

This node represents comparing two 32-bit integers.

```javascript
function compare(a, b) {
  // The 'a > b' comparison might be represented by an Int32Compare node.
  if (a > b) {
    console.log("a is greater than b");
  }
}

compare(5, 3);
```

**4. `StoreTaggedFieldWithWriteBarrier` (Property Assignment):**

This node represents assigning a value to an object's property, including the necessary write barrier for garbage collection.

```javascript
const myObject = {};
// Assigning a value to myObject.y might translate to a StoreTaggedFieldWithWriteBarrier operation.
myObject.y = "hello";
```

**5. `GetIterator` (Iteration):**

This node is used when retrieving an iterator from an iterable object (like an array or string).

```javascript
const myArray = [1, 2, 3];
// When using a for...of loop, a GetIterator node might be used.
for (const item of myArray) {
  console.log(item);
}
```

In summary, this `maglev-ir.cc` file defines the building blocks of the Maglev compiler's intermediate representation, enabling it to translate JavaScript code into efficient machine code by representing various operations and checks as distinct nodes. Each node encapsulates the specific logic and constraints for a particular operation.

Prompt: 
```
这是目录为v8/src/maglev/maglev-ir.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
 ToRegister(input()));
}

void CheckMaps::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  set_temporaries_needed(MapCompare::TemporaryCount(maps_.size()));
}

void CheckMaps::GenerateCode(MaglevAssembler* masm,
                             const ProcessingState& state) {
  Register object = ToRegister(receiver_input());

  // We emit an unconditional deopt if we intersect the map sets and the
  // intersection is empty.
  DCHECK(!maps().is_empty());

  bool maps_include_heap_number = compiler::AnyMapIsHeapNumber(maps());

  // Experimentally figured out map limit (with slack) which allows us to use
  // near jumps in the code below. If --deopt-every-n-times is on, we generate
  // a bit more code, so disable the near jump optimization.
  constexpr int kMapCountForNearJumps = kTaggedSize == 4 ? 10 : 5;
  Label::Distance jump_distance = (maps().size() <= kMapCountForNearJumps &&
                                   v8_flags.deopt_every_n_times <= 0)
                                      ? Label::Distance::kNear
                                      : Label::Distance::kFar;

  Label done;
  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    if (maps_include_heap_number) {
      // Smis count as matching the HeapNumber map, so we're done.
      __ JumpIfSmi(object, &done, jump_distance);
    } else {
      __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kWrongMap);
    }
  }

  MapCompare map_compare(masm, object, maps_.size());
  size_t map_count = maps().size();
  for (size_t i = 0; i < map_count - 1; ++i) {
    Handle<Map> map = maps().at(i).object();
    map_compare.Generate(map, kEqual, &done, jump_distance);
  }
  Handle<Map> last_map = maps().at(map_count - 1).object();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongMap);
  map_compare.Generate(last_map, kNotEqual, fail);
  __ bind(&done);
}

int CheckMapsWithMigration::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kTryMigrateInstance)->nargs, 1);
  return 1;
}

void CheckMapsWithMigration::SetValueLocationConstraints() {
  UseRegister(receiver_input());
  set_temporaries_needed(MapCompare::TemporaryCount(maps_.size()));
}

void CheckMapsWithMigration::GenerateCode(MaglevAssembler* masm,
                                          const ProcessingState& state) {
  // We emit an unconditional deopt if we intersect the map sets and the
  // intersection is empty.
  DCHECK(!maps().is_empty());

  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(receiver_input());

  bool maps_include_heap_number = compiler::AnyMapIsHeapNumber(maps());

  ZoneLabelRef map_checks(masm), done(masm);

  if (check_type() == CheckType::kOmitHeapObjectCheck) {
    __ AssertNotSmi(object);
  } else {
    if (maps_include_heap_number) {
      // Smis count as matching the HeapNumber map, so we're done.
      __ JumpIfSmi(object, *done);
    } else {
      __ EmitEagerDeoptIfSmi(this, object, DeoptimizeReason::kWrongMap);
    }
  }

  // If we jump from here from the deferred code (below), we need to reload
  // the map.
  __ bind(*map_checks);

  RegisterSnapshot save_registers = register_snapshot();
  // Make sure that the object register is not clobbered by the
  // Runtime::kMigrateInstance runtime call. It's ok to clobber the register
  // where the object map is, since the map is reloaded after the runtime call.
  save_registers.live_registers.set(object);
  save_registers.live_tagged_registers.set(object);

  size_t map_count = maps().size();
  bool has_migration_targets = false;
  MapCompare map_compare(masm, object, maps_.size());
  Handle<Map> map_handle;
  for (size_t i = 0; i < map_count; ++i) {
    map_handle = maps().at(i).object();
    const bool last_map = (i == map_count - 1);
    if (!last_map) {
      map_compare.Generate(map_handle, kEqual, *done);
    }
    if (map_handle->is_migration_target()) {
      has_migration_targets = true;
    }
  }

  if (!has_migration_targets) {
    // Emit deopt for the last map.
    map_compare.Generate(map_handle, kNotEqual,
                         __ GetDeoptLabel(this, DeoptimizeReason::kWrongMap));
  } else {
    map_compare.Generate(
        map_handle, kNotEqual,
        __ MakeDeferredCode(
            [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
               ZoneLabelRef map_checks, MapCompare map_compare,
               CheckMapsWithMigration* node) {
              Label* deopt =
                  __ GetDeoptLabel(node, DeoptimizeReason::kWrongMap);
              // If the map is not deprecated, we fail the map check.
              __ TestInt32AndJumpIfAllClear(
                  FieldMemOperand(map_compare.GetMap(), Map::kBitField3Offset),
                  Map::Bits3::IsDeprecatedBit::kMask, deopt);

              // Otherwise, try migrating the object.
              __ TryMigrateInstance(map_compare.GetObject(), register_snapshot,
                                    deopt);
              __ Jump(*map_checks);
              // We'll need to reload the map since it might have changed; it's
              // done right after the map_checks label.
            },
            save_registers, map_checks, map_compare, this));
    // If the jump to deferred code was not taken, the map was equal to the
    // last map.
  }  // End of the `has_migration_targets` case.
  __ bind(*done);
}

void CheckMapsWithAlreadyLoadedMap::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseRegister(map_input());
}

void CheckMapsWithAlreadyLoadedMap::GenerateCode(MaglevAssembler* masm,
                                                 const ProcessingState& state) {
  Register map = ToRegister(map_input());

  // We emit an unconditional deopt if we intersect the map sets and the
  // intersection is empty.
  DCHECK(!maps().is_empty());

  // CheckMapsWithAlreadyLoadedMap can only be used in contexts where SMIs /
  // HeapNumbers don't make sense (e.g., if we're loading properties from them).
  DCHECK(!compiler::AnyMapIsHeapNumber(maps()));

  // Experimentally figured out map limit (with slack) which allows us to use
  // near jumps in the code below. If --deopt-every-n-times is on, we generate
  // a bit more code, so disable the near jump optimization.
  constexpr int kMapCountForNearJumps = kTaggedSize == 4 ? 10 : 5;
  Label::Distance jump_distance = (maps().size() <= kMapCountForNearJumps &&
                                   v8_flags.deopt_every_n_times <= 0)
                                      ? Label::Distance::kNear
                                      : Label::Distance::kFar;

  Label done;
  size_t map_count = maps().size();
  for (size_t i = 0; i < map_count - 1; ++i) {
    Handle<Map> map_at_i = maps().at(i).object();
    __ CompareTaggedAndJumpIf(map, map_at_i, kEqual, &done, jump_distance);
  }
  Handle<Map> last_map = maps().at(map_count - 1).object();
  Label* fail = __ GetDeoptLabel(this, DeoptimizeReason::kWrongMap);
  __ CompareTaggedAndJumpIf(map, last_map, kNotEqual, fail);
  __ bind(&done);
}

int MigrateMapIfNeeded::MaxCallStackArgs() const {
  DCHECK_EQ(Runtime::FunctionForId(Runtime::kTryMigrateInstance)->nargs, 1);
  return 1;
}

void MigrateMapIfNeeded::SetValueLocationConstraints() {
  UseRegister(map_input());
  UseRegister(object_input());
  DefineSameAsFirst(this);
}

void MigrateMapIfNeeded::GenerateCode(MaglevAssembler* masm,
                                      const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register object = ToRegister(object_input());
  Register map = ToRegister(map_input());
  DCHECK_EQ(map, ToRegister(result()));

  ZoneLabelRef done(masm);

  RegisterSnapshot save_registers = register_snapshot();
  // Make sure that the object register are not clobbered by TryMigrateInstance
  // (which does a runtime call). We need the object register for reloading the
  // map. It's okay to clobber the map register, since we will always reload (or
  // deopt) after the runtime call.
  save_registers.live_registers.set(object);
  save_registers.live_tagged_registers.set(object);

  // If the map is deprecated, jump to the deferred code which will migrate it.
  __ TestInt32AndJumpIfAnySet(
      FieldMemOperand(map, Map::kBitField3Offset),
      Map::Bits3::IsDeprecatedBit::kMask,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, RegisterSnapshot register_snapshot,
             ZoneLabelRef done, Register object, Register map,
             MigrateMapIfNeeded* node) {
            Label* deopt = __ GetDeoptLabel(node, DeoptimizeReason::kWrongMap);
            __ TryMigrateInstance(object, register_snapshot, deopt);
            // Reload the map since TryMigrateInstance might have changed it.
            __ LoadTaggedField(map, object, HeapObject::kMapOffset);
            __ Jump(*done);
          },
          save_registers, done, object, map, this));

  // No migration needed. Return the original map. We already have it in the
  // first input register which is the same as the return register.

  __ bind(*done);
}

int DeleteProperty::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kDeleteProperty>::type;
  return D::GetStackParameterCount();
}
void DeleteProperty::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kDeleteProperty>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(object(), D::GetRegisterParameter(D::kObject));
  UseFixed(key(), D::GetRegisterParameter(D::kKey));
  DefineAsFixed(this, kReturnRegister0);
}
void DeleteProperty::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  __ CallBuiltin<Builtin::kDeleteProperty>(
      context(),                              // context
      object(),                               // object
      key(),                                  // key
      Smi::FromInt(static_cast<int>(mode()))  // language mode
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int ForInPrepare::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kForInPrepare>::type;
  return D::GetStackParameterCount();
}
void ForInPrepare::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kForInPrepare>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(enumerator(), D::GetRegisterParameter(D::kEnumerator));
  DefineAsFixed(this, kReturnRegister0);
}
void ForInPrepare::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  __ CallBuiltin<Builtin::kForInPrepare>(
      context(),                                    // context
      enumerator(),                                 // enumerator
      TaggedIndex::FromIntptr(feedback().index()),  // feedback slot
      feedback().vector                             // feedback vector
  );
}

int ForInNext::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kForInNext>::type;
  return D::GetStackParameterCount();
}
void ForInNext::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kForInNext>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(receiver(), D::GetRegisterParameter(D::kReceiver));
  UseFixed(cache_array(), D::GetRegisterParameter(D::kCacheArray));
  UseFixed(cache_type(), D::GetRegisterParameter(D::kCacheType));
  UseFixed(cache_index(), D::GetRegisterParameter(D::kCacheIndex));
  DefineAsFixed(this, kReturnRegister0);
}
void ForInNext::GenerateCode(MaglevAssembler* masm,
                             const ProcessingState& state) {
  __ CallBuiltin<Builtin::kForInNext>(context(),           // context
                                      feedback().index(),  // feedback slot
                                      receiver(),          // receiver
                                      cache_array(),       // cache array
                                      cache_type(),        // cache type
                                      cache_index(),       // cache index
                                      feedback().vector    // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

int GetIterator::MaxCallStackArgs() const {
  using D = CallInterfaceDescriptorFor<Builtin::kGetIteratorWithFeedback>::type;
  return D::GetStackParameterCount();
}
void GetIterator::SetValueLocationConstraints() {
  using D = CallInterfaceDescriptorFor<Builtin::kGetIteratorWithFeedback>::type;
  UseFixed(context(), kContextRegister);
  UseFixed(receiver(), D::GetRegisterParameter(D::kReceiver));
  DefineAsFixed(this, kReturnRegister0);
}
void GetIterator::GenerateCode(MaglevAssembler* masm,
                               const ProcessingState& state) {
  __ CallBuiltin<Builtin::kGetIteratorWithFeedback>(
      context(),                             // context
      receiver(),                            // receiver
      TaggedIndex::FromIntptr(load_slot()),  // feedback load slot
      TaggedIndex::FromIntptr(call_slot()),  // feedback call slot
      feedback()                             // feedback vector
  );
  masm->DefineExceptionHandlerAndLazyDeoptPoint(this);
}

void Int32Compare::SetValueLocationConstraints() {
  UseRegister(left_input());
  if (right_input().node()->Is<Int32Constant>()) {
    UseAny(right_input());
  } else {
    UseRegister(right_input());
  }
  DefineAsRegister(this);
}

void Int32Compare::GenerateCode(MaglevAssembler* masm,
                                const ProcessingState& state) {
  Register result = ToRegister(this->result());
  Label is_true, end;
  if (Int32Constant* constant =
          right_input().node()->TryCast<Int32Constant>()) {
    int32_t right_value = constant->value();
    __ CompareInt32AndJumpIf(ToRegister(left_input()), right_value,
                             ConditionFor(operation()), &is_true,
                             Label::Distance::kNear);
  } else {
    __ CompareInt32AndJumpIf(
        ToRegister(left_input()), ToRegister(right_input()),
        ConditionFor(operation()), &is_true, Label::Distance::kNear);
  }
  // TODO(leszeks): Investigate loading existing materialisations of roots here,
  // if available.
  __ LoadRoot(result, RootIndex::kFalseValue);
  __ jmp(&end);
  {
    __ bind(&is_true);
    __ LoadRoot(result, RootIndex::kTrueValue);
  }
  __ bind(&end);
}

void Int32ToBoolean::SetValueLocationConstraints() {
  UseRegister(value());
  DefineAsRegister(this);
}

void Int32ToBoolean::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  Register result = ToRegister(this->result());
  Label is_true, end;
  __ CompareInt32AndJumpIf(ToRegister(value()), 0, kNotEqual, &is_true,
                           Label::Distance::kNear);
  // TODO(leszeks): Investigate loading existing materialisations of roots here,
  // if available.
  __ LoadRoot(result, flip() ? RootIndex::kTrueValue : RootIndex::kFalseValue);
  __ jmp(&end);
  {
    __ bind(&is_true);
    __ LoadRoot(result,
                flip() ? RootIndex::kFalseValue : RootIndex::kTrueValue);
  }
  __ bind(&end);
}

void Float64Compare::SetValueLocationConstraints() {
  UseRegister(left_input());
  UseRegister(right_input());
  DefineAsRegister(this);
}

void Float64Compare::GenerateCode(MaglevAssembler* masm,
                                  const ProcessingState& state) {
  DoubleRegister left = ToDoubleRegister(left_input());
  DoubleRegister right = ToDoubleRegister(right_input());
  Register result = ToRegister(this->result());
  Label is_false, end;
  __ CompareFloat64AndJumpIf(left, right,
                             NegateCondition(ConditionForFloat64(operation())),
                             &is_false, &is_false, Label::Distance::kNear);
  // TODO(leszeks): Investigate loading existing materialisations of roots here,
  // if available.
  __ LoadRoot(result, RootIndex::kTrueValue);
  __ Jump(&end);
  {
    __ bind(&is_false);
    __ LoadRoot(result, RootIndex::kFalseValue);
  }
  __ bind(&end);
}

void Float64ToBoolean::SetValueLocationConstraints() {
  UseRegister(value());
  set_double_temporaries_needed(1);
  DefineAsRegister(this);
}
void Float64ToBoolean::GenerateCode(MaglevAssembler* masm,
                                    const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  DoubleRegister double_scratch = temps.AcquireDouble();
  Register result = ToRegister(this->result());
  Label is_false, end;

  __ Move(double_scratch, 0.0);
  __ CompareFloat64AndJumpIf(ToDoubleRegister(value()), double_scratch, kEqual,
                             &is_false, &is_false, Label::Distance::kNear);

  __ LoadRoot(result, flip() ? RootIndex::kFalseValue : RootIndex::kTrueValue);
  __ Jump(&end);
  {
    __ bind(&is_false);
    __ LoadRoot(result,
                flip() ? RootIndex::kTrueValue : RootIndex::kFalseValue);
  }
  __ bind(&end);
}

void CheckedHoleyFloat64ToFloat64::SetValueLocationConstraints() {
  UseRegister(input());
  DefineSameAsFirst(this);
  set_temporaries_needed(1);
}
void CheckedHoleyFloat64ToFloat64::GenerateCode(MaglevAssembler* masm,
                                                const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  __ JumpIfHoleNan(ToDoubleRegister(input()), temps.Acquire(),
                   __ GetDeoptLabel(this, DeoptimizeReason::kHole));
}

void LoadDoubleField::SetValueLocationConstraints() {
  UseRegister(object_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
}
void LoadDoubleField::GenerateCode(MaglevAssembler* masm,
                                   const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register tmp = temps.Acquire();
  Register object = ToRegister(object_input());
  __ AssertNotSmi(object);
  __ LoadTaggedField(tmp, object, offset());
  __ AssertNotSmi(tmp);
  __ LoadHeapNumberValue(ToDoubleRegister(result()), tmp);
}

template <typename T>
void AbstractLoadTaggedField<T>::SetValueLocationConstraints() {
  UseRegister(object_input());
  DefineAsRegister(this);
}
template <typename T>
void AbstractLoadTaggedField<T>::GenerateCode(MaglevAssembler* masm,
                                              const ProcessingState& state) {
  Register object = ToRegister(object_input());
  __ AssertNotSmi(object);
  if (this->decompresses_tagged_result()) {
    __ LoadTaggedField(ToRegister(result()), object, offset());
  } else {
    __ LoadTaggedFieldWithoutDecompressing(ToRegister(result()), object,
                                           offset());
  }
}

void LoadTaggedFieldForScriptContextSlot::SetValueLocationConstraints() {
  UseRegister(context());
  set_temporaries_needed(2);
  set_double_temporaries_needed(1);
  DefineAsRegister(this);
}

void LoadTaggedFieldForScriptContextSlot::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  MaglevAssembler::TemporaryRegisterScope temps(masm);
  Register script_context = ToRegister(context());
  Register value = ToRegister(result());
  Register scratch = temps.Acquire();
  ZoneLabelRef done(masm);
  __ AssertObjectType(script_context, SCRIPT_CONTEXT_TYPE,
                      AbortReason::kUnexpectedInstanceType);

  // Be sure to not clobber script_context.
  if (value == script_context) {
    Register tmp = temps.Acquire();
    __ Move(tmp, script_context);
    script_context = tmp;
  }

  // Load value from context.
  __ LoadTaggedField(value, script_context, offset());

  // Check side table if HeapNumber.
  __ JumpIfSmi(value, *done);
  __ CompareMapWithRoot(value, RootIndex::kHeapNumberMap, scratch);
  __ JumpToDeferredIf(
      kEqual,
      [](MaglevAssembler* masm, Register script_context, Register result_reg,
         Register scratch, LoadTaggedFieldForScriptContextSlot* node,
         ZoneLabelRef done) {
        Label property_loaded;
        // Load side table.
        // TODO(victorgomes): Should we hoist the side_table?
        __ LoadTaggedField(scratch, script_context,
                           Context::OffsetOfElementAt(
                               Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX));
        __ LoadTaggedField(
            scratch, scratch,
            FixedArray::OffsetOfElementAt(node->index() -
                                          Context::MIN_CONTEXT_EXTENDED_SLOTS));

        __ JumpIfSmi(scratch, &property_loaded);
        __ AssertObjectType(scratch, CONTEXT_SIDE_PROPERTY_CELL_TYPE,
                            AbortReason::kUnexpectedInstanceType);
        __ LoadTaggedField(scratch, scratch,
                           ContextSidePropertyCell::kPropertyDetailsRawOffset);
        __ bind(&property_loaded);

        __ CompareTaggedAndJumpIf(scratch,
                                  ContextSidePropertyCell::MutableHeapNumber(),
                                  kNotEqual, *done);

        MaglevAssembler::TemporaryRegisterScope temps(masm);
        DoubleRegister double_value = temps.AcquireDouble();
        __ LoadHeapNumberValue(double_value, result_reg);
        __ AllocateHeapNumber(node->register_snapshot(), result_reg,
                              double_value);

        __ Jump(*done);
      },
      script_context, value, scratch, this, done);

  __ bind(*done);
}

void LoadTaggedFieldByFieldIndex::SetValueLocationConstraints() {
  UseRegister(object_input());
  UseAndClobberRegister(index_input());
  DefineAsRegister(this);
  set_temporaries_needed(1);
  set_double_temporaries_needed(1);
}
void LoadTaggedFieldByFieldIndex::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
  Register object = ToRegister(object_input());
  Register field_index = ToRegister(index_input());
  Register result_reg = ToRegister(result());
  __ AssertNotSmi(object);
  __ AssertSmi(field_index);

  ZoneLabelRef done(masm);

  // For in-object properties, the field_index is encoded as:
  //
  //      field_index = array_index | is_double_bit | smi_tag
  //                  = array_index << (1+kSmiTagBits)
  //                        + is_double_bit << kSmiTagBits
  //
  // The value we want is at the field offset:
  //
  //      (array_index << kTaggedSizeLog2) + JSObject::kHeaderSize
  //
  // We could get field_index from array_index by shifting away the double bit
  // and smi tag, followed by shifting back up again, but this means shifting
  // twice:
  //
  //      ((field_index >> kSmiTagBits >> 1) << kTaggedSizeLog2
  //          + JSObject::kHeaderSize
  //
  // Instead, we can do some rearranging to get the offset with either a single
  // small shift, or no shift at all:
  //
  //      (array_index << kTaggedSizeLog2) + JSObject::kHeaderSize
  //
  //    [Split shift to match array_index component of field_index]
  //    = (
  //        (array_index << 1+kSmiTagBits)) << (kTaggedSizeLog2-1-kSmiTagBits)
  //      ) + JSObject::kHeaderSize
  //
  //    [Substitute in field_index]
  //    = (
  //        (field_index - is_double_bit << kSmiTagBits)
  //           << (kTaggedSizeLog2-1-kSmiTagBits)
  //      ) + JSObject::kHeaderSize
  //
  //    [Fold together the constants]
  //    = (field_index << (kTaggedSizeLog2-1-kSmiTagBits)
  //          + (JSObject::kHeaderSize - (is_double_bit << (kTaggedSizeLog2-1)))
  //
  // Note that this results in:
  //
  //     * No shift when kSmiTagBits == kTaggedSizeLog2 - 1, which is the case
  //       when pointer compression is on.
  //     * A shift of 1 when kSmiTagBits == 1 and kTaggedSizeLog2 == 3, which
  //       is the case when pointer compression is off but Smis are 31 bit.
  //     * A shift of 2 when kSmiTagBits == 0 and kTaggedSizeLog2 == 3, which
  //       is the case when pointer compression is off, Smis are 32 bit, and
  //       the Smi was untagged to int32 already.
  //
  // These shifts are small enough to encode in the load operand.
  //
  // For out-of-object properties, the encoding is:
  //
  //     field_index = (-1 - array_index) | is_double_bit | smi_tag
  //                 = (-1 - array_index) << (1+kSmiTagBits)
  //                       + is_double_bit << kSmiTagBits
  //                 = -array_index << (1+kSmiTagBits)
  //                       - 1 << (1+kSmiTagBits) + is_double_bit << kSmiTagBits
  //                 = -array_index << (1+kSmiTagBits)
  //                       - 2 << kSmiTagBits + is_double_bit << kSmiTagBits
  //                 = -array_index << (1+kSmiTagBits)
  //                       (is_double_bit - 2) << kSmiTagBits
  //
  // The value we want is in the property array at offset:
  //
  //      (array_index << kTaggedSizeLog2) + OFFSET_OF_DATA_START(FixedArray)
  //
  //    [Split shift to match array_index component of field_index]
  //    = (array_index << (1+kSmiTagBits)) << (kTaggedSizeLog2-1-kSmiTagBits)
  //        + OFFSET_OF_DATA_START(FixedArray)
  //
  //    [Substitute in field_index]
  //    = (-field_index - (is_double_bit - 2) << kSmiTagBits)
  //        << (kTaggedSizeLog2-1-kSmiTagBits)
  //        + OFFSET_OF_DATA_START(FixedArray)
  //
  //    [Fold together the constants]
  //    = -field_index << (kTaggedSizeLog2-1-kSmiTagBits)
  //        + OFFSET_OF_DATA_START(FixedArray)
  //        - (is_double_bit - 2) << (kTaggedSizeLog2-1))
  //
  // This allows us to simply negate the field_index register and do a load with
  // otherwise constant offset and the same scale factor as for in-object
  // properties.

  static constexpr int kSmiTagBitsInValue = SmiValuesAre32Bits() ? 0 : 1;
  static_assert(kSmiTagBitsInValue == 32 - kSmiValueSize);
  if (SmiValuesAre32Bits()) {
    __ SmiUntag(field_index);
  }

  static constexpr int scale = 1 << (kTaggedSizeLog2 - 1 - kSmiTagBitsInValue);

  // Check if field is a mutable double field.
  static constexpr int32_t kIsDoubleBitMask = 1 << kSmiTagBitsInValue;
  __ TestInt32AndJumpIfAnySet(
      field_index, kIsDoubleBitMask,
      __ MakeDeferredCode(
          [](MaglevAssembler* masm, Register object, Register field_index,
             Register result_reg, RegisterSnapshot register_snapshot,
             ZoneLabelRef done) {
            // The field is a Double field, a.k.a. a mutable HeapNumber.
            static constexpr int kIsDoubleBit = 1;

            // Check if field is in-object or out-of-object. The is_double bit
            // value doesn't matter, since negative values will stay negative.
            Label if_outofobject, loaded_field;
            __ CompareInt32AndJumpIf(field_index, 0, kLessThan,
                                     &if_outofobject);

            // The field is located in the {object} itself.
            {
              // See giant comment above.
              if (SmiValuesAre31Bits() && kTaggedSize != kSystemPointerSize) {
                // We haven't untagged, so we need to sign extend.
                __ SignExtend32To64Bits(field_index, field_index);
              }
              __ LoadTaggedFieldByIndex(
                  result_reg, object, field_index, scale,
                  JSObject::kHeaderSize -
                      (kIsDoubleBit << (kTaggedSizeLog2 - 1)));
              __ Jump(&loaded_field);
            }

            __ bind(&if_outofobject);
            {
              MaglevAssembler::TemporaryRegisterScope temps(masm);
              Register property_array = temps.Acquire();
              // Load the property array.
              __ LoadTaggedField(
                  property_array,
                  FieldMemOperand(object, JSObject::kPropertiesOrHashOffset));

              // See giant comment above. No need to sign extend, negate will
              // handle it.
              __ NegateInt32(field_index);
              __ LoadTaggedFieldByIndex(
                  result_reg, property_array, field_index, scale,
                  OFFSET_OF_DATA_START(FixedArray) -
                      ((2 - kIsDoubleBit) << (kTaggedSizeLog2 - 1)));
              __ Jump(&loaded_field);
            }

            __ bind(&loaded_field);
            // We may have transitioned in-place away from double, so check that
            // this is a HeapNumber -- otherwise the load is fine and we don't
            // need to copy anything anyway.
            __ JumpIfSmi(result_reg, *done);
            MaglevAssembler::TemporaryRegisterScope temps(masm);
            Register map = temps.Acquire();
            // Hack: The temporary allocated for `map` might alias the result
            // register. If it does, use the field_index register as a temporary
            // instead (since it's clobbered anyway).
            // TODO(leszeks): Extend the result register's lifetime to overlap
            // the temporaries, so that this alias isn't possible.
            if (map == result_reg) {
              DCHECK_NE(map, field_index);
              map = field_index;
            }
            __ LoadMapForCompare(map, result_reg);
            __ JumpIfNotRoot(map, RootIndex::kHeapNumberMap, *done);
            DoubleRegister double_value = temps.AcquireDouble();
            __ LoadHeapNumberValue(double_value, result_reg);
            __ AllocateHeapNumber(register_snapshot, result_reg, double_value);
            __ Jump(*done);
          },
          object, field_index, result_reg, register_snapshot(), done));

  // The field is a proper Tagged field on {object}. The {field_index} is
  // shifted to the left by one in the code below.
  {
    static constexpr int kIsDoubleBit = 0;

    // Check if field is in-object or out-of-object. The is_double bit value
    // doesn't matter, since negative values will stay negative.
    Label if_outofobject;
    __ CompareInt32AndJumpIf(field_index, 0, kLessThan, &if_outofobject);

    // The field is located in the {object} itself.
    {
      // See giant comment above.
      if (SmiValuesAre31Bits() && kTaggedSize != kSystemPointerSize) {
        // We haven't untagged, so we need to sign extend.
        __ SignExtend32To64Bits(field_index, field_index);
      }
      __ LoadTaggedFieldByIndex(
          result_reg, object, field_index, scale,
          JSObject::kHeaderSize - (kIsDoubleBit << (kTaggedSizeLog2 - 1)));
      __ Jump(*done);
    }

    __ bind(&if_outofobject);
    {
      MaglevAssembler::TemporaryRegisterScope temps(masm);
      Register property_array = temps.Acquire();
      // Load the property array.
      __ LoadTaggedField(
          property_array,
          FieldMemOperand(object, JSObject::kPropertiesOrHashOffset));

      // See giant comment above. No need to sign extend, negate will handle it.
      __ NegateInt32(field_index);
      __ LoadTaggedFieldByIndex(
          result_reg, property_array, field_index, scale,
          OFFSET_OF_DATA_START(FixedArray) -
              ((2 - kIsDoubleBit) << (kTaggedSizeLog2 - 1)));
      // Fallthrough to `done`.
    }
  }

  __ bind(*done);
}

void LoadFixedArrayElement::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  DefineAsRegister(this);
}
void LoadFixedArrayElement::GenerateCode(MaglevAssembler* masm,
                                         const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  Register result_reg = ToRegister(result());
  if (this->decompresses_tagged_result()) {
    __ LoadFixedArrayElement(result_reg, elements, index);
  } else {
    __ LoadFixedArrayElementWithoutDecompressing(result_reg, elements, index);
  }
}

void LoadFixedDoubleArrayElement::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  DefineAsRegister(this);
}
void LoadFixedDoubleArrayElement::GenerateCode(MaglevAssembler* masm,
                                               const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  DoubleRegister result_reg = ToDoubleRegister(result());
  __ LoadFixedDoubleArrayElement(result_reg, elements, index);
}

void LoadHoleyFixedDoubleArrayElement::SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  DefineAsRegister(this);
}
void LoadHoleyFixedDoubleArrayElement::GenerateCode(
    MaglevAssembler* masm, const ProcessingState& state) {
  Register elements = ToRegister(elements_input());
  Register index = ToRegister(index_input());
  DoubleRegister result_reg = ToDoubleRegister(result());
  __ LoadFixedDoubleArrayElement(result_reg, elements, index);
}

void LoadHoleyFixedDoubleArrayElementCheckedNotHole::
    SetValueLocationConstraints() {
  UseRegister(elements_input());
  UseRegister(index_input());
  DefineAsRegister(this);
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
"""


```