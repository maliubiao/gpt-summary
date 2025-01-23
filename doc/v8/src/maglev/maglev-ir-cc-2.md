Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-ir.cc`.

Here's a breakdown of the code's key functionalities, going through each class and its `GenerateCode` method:

1. **`CheckMaps`**: Checks the map (type information) of an object against a set of allowed maps. Deoptimizes if the map doesn't match. Handles potential HeapNumber cases.
2. **`CheckMapsWithMigration`**: Similar to `CheckMaps`, but also attempts to migrate the object to a more recent map if the current map is deprecated.
3. **`CheckMapsWithAlreadyLoadedMap`**: Checks an object's map against a set of allowed maps, assuming the map is already loaded in a register.
4. **`MigrateMapIfNeeded`**: Checks if an object's map is deprecated and, if so, attempts to migrate the object.
5. **`DeleteProperty`**: Calls the `DeleteProperty` builtin to delete a property from an object.
6. **`ForInPrepare`**: Calls the `ForInPrepare` builtin, likely setting up for a `for...in` loop.
7. **`ForInNext`**: Calls the `ForInNext` builtin to get the next property in a `for...in` loop.
8. **`GetIterator`**: Calls the `GetIteratorWithFeedback` builtin to get an iterator for an object.
9. **`Int32Compare`**: Compares two 32-bit integers and produces a boolean result.
10. **`Int32ToBoolean`**: Converts a 32-bit integer to a boolean.
11. **`Float64Compare`**: Compares two 64-bit floating-point numbers and produces a boolean result.
12. **`Float64ToBoolean`**: Converts a 64-bit floating-point number to a boolean.
13. **`CheckedHoleyFloat64ToFloat64`**: Checks if a 64-bit floating-point number is a hole (`NaN`) and deoptimizes if it is.
14. **`LoadDoubleField`**: Loads a double-precision floating-point value from a field of an object.
15. **`AbstractLoadTaggedField`**: (Template) Loads a tagged value from a field of an object. Can optionally avoid decompressing the tag.
16. **`LoadTaggedFieldForScriptContextSlot`**: Loads a tagged value from a slot in a script context, handling potential HeapNumber cases.
17. **`LoadTaggedFieldByFieldIndex`**: Loads a tagged value from an object's field, determined by a field index, handling both in-object and out-of-object properties, and mutable double fields.
18. **`LoadFixedArrayElement`**: Loads an element from a `FixedArray`.
19. **`LoadFixedDoubleArrayElement`**: Loads a double-precision floating-point element from a `FixedDoubleArray`.
20. **`LoadHoleyFixedDoubleArrayElement`**: Loads a double-precision floating-point element from a potentially holey `FixedDoubleArray`.

The general theme is **type checking, property access (load/delete), iteration support, and basic arithmetic/comparison operations**, all within the context of V8's Maglev compiler.

Now, let's formulate the response based on these observations.
这是v8源代码文件 `v8/src/maglev/maglev-ir.cc` 的第三部分，主要定义了 Maglev 编译器的中间表示（IR）中与 **类型检查、属性操作、迭代以及数值比较和转换** 相关的节点的功能。

根据您提供的代码片段，我们可以归纳出以下功能：

**核心功能归纳：**

这部分代码主要定义了以下几种 Maglev IR 节点的代码生成逻辑：

*   **类型检查 (Type Checking):**
    *   `CheckMaps`: 检查一个对象的 map（隐藏类）是否在预期的 map 集合中。如果不在，则触发去优化（deoptimization）。
    *   `CheckMapsWithMigration`:  类似于 `CheckMaps`，但当对象的 map 是一个迁移目标时，会尝试进行对象迁移。
    *   `CheckMapsWithAlreadyLoadedMap`:  与 `CheckMaps` 类似，但假设对象的 map 已经被加载到寄存器中。
*   **对象迁移 (Object Migration):**
    *   `MigrateMapIfNeeded`: 检查一个对象的 map 是否已过时（deprecated），如果是，则尝试迁移该对象。
*   **属性操作 (Property Operations):**
    *   `DeleteProperty`: 调用内置函数 `DeleteProperty` 来删除对象的属性。
*   **迭代 (Iteration):**
    *   `ForInPrepare`: 调用内置函数 `ForInPrepare`，用于准备 `for...in` 循环。
    *   `ForInNext`: 调用内置函数 `ForInNext`，用于 `for...in` 循环中获取下一个属性。
    *   `GetIterator`: 调用内置函数 `GetIteratorWithFeedback`，用于获取对象的迭代器。
*   **数值比较 (Numeric Comparison):**
    *   `Int32Compare`: 比较两个 32 位整数。
    *   `Float64Compare`: 比较两个 64 位浮点数。
*   **数值类型转换 (Numeric Type Conversion):**
    *   `Int32ToBoolean`: 将 32 位整数转换为布尔值。
    *   `Float64ToBoolean`: 将 64 位浮点数转换为布尔值。
    *   `CheckedHoleyFloat64ToFloat64`: 检查一个可能是 "hole" (NaN) 的 64 位浮点数，如果为 hole 则触发去优化。
*   **字段加载 (Field Loading):**
    *   `LoadDoubleField`: 从对象中加载一个双精度浮点数字段。
    *   `AbstractLoadTaggedField`:  (模板类) 从对象中加载一个带标签的字段。
    *   `LoadTaggedFieldForScriptContextSlot`: 从脚本上下文的槽中加载带标签的字段，并处理可能是 HeapNumber 的情况。
    *   `LoadTaggedFieldByFieldIndex`: 通过字段索引从对象中加载带标签的字段，支持内联属性和外部属性，并处理双精度浮点数字段。
    *   `LoadFixedArrayElement`: 从 `FixedArray` 中加载元素。
    *   `LoadFixedDoubleArrayElement`: 从 `FixedDoubleArray` 中加载双精度浮点数元素。
    *   `LoadHoleyFixedDoubleArrayElement`: 从可能包含 "hole" 的 `FixedDoubleArray` 中加载双精度浮点数元素。

**关于文件类型：**

`v8/src/maglev/maglev-ir.cc` 以 `.cc` 结尾，因此是 **C++ 源代码**，而不是 Torque 源代码。Torque 源代码文件以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例：**

这些 IR 节点直接对应着 JavaScript 的一些核心功能。

*   **类型检查:**  JavaScript 是动态类型语言，V8 需要在运行时检查对象的类型。例如，当你访问一个对象的属性时，V8 需要确保该对象是期望的类型。

    ```javascript
    function foo(obj) {
      return obj.x; // V8 需要检查 obj 是否有属性 x
    }

    foo({ x: 1 }); // 正常
    foo(null);     // 会报错，因为 null 没有属性 x
    ```

*   **对象迁移:** 当 JavaScript 对象的结构发生变化时（例如添加或删除属性），V8 可以将其迁移到新的隐藏类以优化性能。

    ```javascript
    const obj = { a: 1 };
    obj.b = 2; // 可能会触发对象迁移
    ```

*   **属性操作:** JavaScript 允许动态地添加和删除对象的属性。

    ```javascript
    const obj = { a: 1 };
    delete obj.a;
    ```

*   **迭代:** `for...in` 循环用于枚举对象的可枚举属性。

    ```javascript
    const obj = { a: 1, b: 2 };
    for (const key in obj) {
      console.log(key);
    }
    ```

*   **数值比较:** JavaScript 中的 `==`, `===`, `<`, `>`, `<=`, `>=` 等运算符用于比较数值。

    ```javascript
    const a = 10;
    const b = 5;
    console.log(a > b); // true

    const x = 1.1;
    const y = 2.2;
    console.log(x < y); // true
    ```

*   **数值类型转换:** JavaScript 会在某些情况下自动进行类型转换。

    ```javascript
    console.log(10 ? 'true' : 'false'); // true (10 被转换为布尔值 true)
    console.log(0 ? 'true' : 'false');  // false (0 被转换为布尔值 false)
    console.log(1.5 ? 'true' : 'false'); // true
    console.log(0.0 ? 'true' : 'false'); // false
    ```

*   **字段加载:** 访问对象的属性实际上是从对象的内存布局中加载相应字段的值。

    ```javascript
    const obj = { x: 10 };
    console.log(obj.x); // V8 需要加载对象 obj 的 "x" 字段
    ```

**代码逻辑推理和假设输入输出：**

以 `Int32Compare` 为例：

**假设输入：**

*   `left_input()` 的值为整数 `5`。
*   `right_input()` 的值为整数 `10`。
*   `operation()` 为小于 (`kLessThan`)。

**输出：**

*   `result()` 的值为布尔值 `true`，因为 `5 < 10`。

**假设输入：**

*   `left_input()` 的值为整数 `15`。
*   `right_input()` 的值为整数 `7`。
*   `operation()` 为大于等于 (`kGreaterThanOrEqual`)。

**输出：**

*   `result()` 的值为布尔值 `true`，因为 `15 >= 7`。

**用户常见的编程错误举例：**

*   **类型检查错误:**  期望一个对象是特定类型，但实际传入了其他类型的对象，可能导致运行时错误或去优化。

    ```javascript
    function processArray(arr) {
      for (let i = 0; i < arr.length; i++) { // 假设 arr 是数组
        console.log(arr[i]);
      }
    }

    processArray([1, 2, 3]); // 正常
    processArray({ length: 2, 0: 'a', 1: 'b' }); // 可能导致意外行为或错误，因为对象不是真正的数组
    processArray(null); // 报错，null 没有 length 属性
    ```

*   **在对象为 null 或 undefined 时访问属性:** 这会导致运行时错误。

    ```javascript
    function printName(obj) {
      console.log(obj.name); // 如果 obj 是 null 或 undefined，则会报错
    }

    printName({ name: 'Alice' });
    printName(null); // TypeError: Cannot read properties of null
    ```

*   **对非数值类型进行数值运算或比较:** JavaScript 会尝试进行类型转换，但结果可能不是预期的。

    ```javascript
    console.log("5" > 3);   // true (字符串 "5" 被转换为数字 5)
    console.log("abc" > 3); // false (字符串 "abc" 被转换为 NaN，NaN 与任何数字比较都返回 false)
    ```

总而言之，这部分 `maglev-ir.cc` 代码定义了 Maglev 编译器在生成机器码时处理 JavaScript 类型、对象属性、迭代和基本数值操作的关键步骤，并处理了一些潜在的运行时错误和优化机会。

### 提示词
```
这是目录为v8/src/maglev/maglev-ir.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-ir.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  D
```