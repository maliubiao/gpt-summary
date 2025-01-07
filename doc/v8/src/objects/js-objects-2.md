Response: The user wants a summary of the C++ code in `v8/src/objects/js-objects.cc`, specifically part 3 of 4. The summary should cover the functionality and explain how it relates to JavaScript features, providing JavaScript examples.

Based on the code, here's a breakdown of the key functionalities in this section:

1. **Object Property Migration:** Functions like `MigrateToMap`, `MigrateFastToFast`, `MigrateFastToSlow`, and `MigrateSlowToFast` are central. These handle the process of changing an object's hidden class (Map) due to property additions, deletions, or attribute changes.
2. **Property Manipulation:**  Functions like `AddProperty`, `DefineOwnPropertyIgnoreAttributes`, `SetOwnPropertyIgnoreAttributes`, and `DeletePropertyWithInterceptor` deal with adding, defining, setting, and deleting properties on JavaScript objects.
3. **Property Normalization:** The `NormalizeProperties` function is used to transition objects to a slower, more flexible property storage mechanism (dictionary mode).
4. **Element Handling:** Functions like `GetElementsTransitionMap`, `AllocateStorageForMap`, and `NormalizeElements` focus on how JavaScript object elements (indexed properties) are managed and transitioned between different storage types.
5. **Preventing Extensions and Integrity Levels:** Functions like `PreventExtensions`, `IsExtensible`, and `TestIntegrityLevel` relate to the mechanisms for preventing the addition of new properties (sealing and freezing) and checking if an object adheres to these restrictions.
6. **Accessor Properties:** Functions like `DefineOwnAccessorIgnoreAttributes` and `SetAccessor` handle the creation and modification of getter/setter properties.
7. **Prototype Optimization:** The `OptimizeAsPrototype` function deals with optimizing objects intended to be used as prototypes for better performance.
8. **Internal Utility Functions:** There are helper functions like `TryFastAddDataProperty`, `TestFastPropertiesIntegrityLevel`, and template functions for applying attributes to dictionaries.

Now, let's connect these functionalities to JavaScript concepts with examples.
这个C++代码文件 `v8/src/objects/js-objects.cc` 的第 3 部分主要负责 **JavaScript 对象的属性管理和内部状态转换**。 它涵盖了对象如何在不同类型的内部表示之间迁移，如何添加、定义和修改属性，以及如何控制对象的扩展性和完整性。

以下是此部分代码的主要功能归纳：

1. **对象 Map 的迁移 (Map Migration):**  这部分代码的核心功能是处理 JavaScript 对象在不同 "形状" 之间的转换。  对象的 "形状" 由其 `Map` 决定，`Map` 存储了对象的结构信息，例如属性的名称、类型和位置。当对象的属性发生变化（例如添加新属性，删除属性，修改属性特性等）时，对象可能需要迁移到新的 `Map`。
    *   `MigrateToMap`:  通用的 Map 迁移函数，根据新旧 `Map` 的类型调用不同的迁移策略。
    *   `MigrateFastToFast`:  当对象在两种快速属性存储模式之间迁移时使用。
    *   `MigrateFastToSlow`:  当对象从快速属性存储模式迁移到慢速的字典模式时使用。
    *   `MigrateSlowToFast`:  当对象从慢速的字典模式迁移回快速属性存储模式时使用。

2. **属性的添加和定义 (Property Addition and Definition):**  这部分代码包含了向 JavaScript 对象添加和定义属性的功能。
    *   `AddProperty`:  向对象添加一个新的数据属性。
    *   `DefineOwnPropertyIgnoreAttributes`:  定义或修改对象自身的属性，并允许忽略某些属性特性。
    *   `SetOwnPropertyIgnoreAttributes`:  设置对象自身属性的值，并允许忽略某些属性特性。
    *   `DefineOwnAccessorIgnoreAttributes`: 定义对象自身的访问器属性（getter/setter）。

3. **属性的规范化 (Property Normalization):**  当对象的属性过于复杂或数量过多时，会从快速属性模式转换到更通用的字典模式。
    *   `NormalizeProperties`: 将对象的属性存储方式规范化到字典模式。

4. **元素 (Elements) 的处理:**  JavaScript 数组和类数组对象拥有索引属性，这部分代码也处理了这些元素的存储和转换。
    *   `GetElementsTransitionMap`: 获取元素类型转换的目标 `Map`。
    *   `AllocateStorageForMap`: 为特定 `Map` 分配存储空间，包括元素存储。
    *   `NormalizeElements`: 将对象的元素存储方式规范化到慢速的字典模式。

5. **防止扩展和完整性级别 (Prevent Extensions and Integrity Levels):**  JavaScript 提供了防止对象添加新属性 (阻止扩展) 以及冻结和密封对象的功能。
    *   `PreventExtensions`:  阻止对象添加新的属性。
    *   `IsExtensible`:  检查对象是否可扩展。
    *   `TestIntegrityLevel`:  测试对象的完整性级别（是否被密封或冻结）。

6. **访问器属性 (Accessor Properties):**  这部分代码包含了设置和处理访问器属性 (getter/setter)。
    *   `SetAccessor`:  设置对象的访问器属性。

7. **原型优化 (Prototype Optimization):**  为了提升性能，V8 会对用作原型的对象进行优化。
    *   `OptimizeAsPrototype`:  将对象优化为原型对象。

**与 JavaScript 功能的关系及示例:**

这部分 C++ 代码直接实现了许多核心的 JavaScript 对象行为。以下是一些 JavaScript 示例以及它们与代码中功能的对应关系：

**1. 对象 Map 的迁移:**

```javascript
const obj = {};
obj.a = 1; // 添加属性 'a'，可能触发 Map 迁移
obj.b = 2; // 添加属性 'b'，也可能触发 Map 迁移
delete obj.a; // 删除属性 'a'，又可能触发 Map 迁移
```

当您向一个 JavaScript 对象添加或删除属性时，V8 内部可能会调用 `MigrateToMap` 或其相关的迁移函数来更新对象的内部表示。

**2. 属性的添加和定义:**

```javascript
const obj = {};
obj.name = "example"; // 相当于调用 AddProperty

Object.defineProperty(obj, 'age', { // 相当于调用 DefineOwnPropertyIgnoreAttributes
  value: 30,
  writable: false,
  enumerable: true,
  configurable: false
});

obj.age = 31; // 由于 writable 为 false，此操作不会生效

Object.defineProperty(obj, 'greeting', { // 定义访问器属性
  get() { return `Hello, ${this.name}!`; },
  set(value) { console.log('Cannot set greeting.'); }
});

console.log(obj.greeting); // 调用 getter

obj.greeting = "Hi"; // 调用 setter
```

`AddProperty` 对应直接赋值操作。 `Object.defineProperty` 的调用会转化为对 `DefineOwnPropertyIgnoreAttributes` 等函数的调用，以设置属性的各种特性。

**3. 属性的规范化:**

```javascript
const obj = {};
for (let i = 0; i < 100; i++) {
  obj[`prop_${i}`] = i; // 大量属性可能导致对象规范化到字典模式
}
```

当对象拥有大量属性时，V8 会自动将其内部存储从快速模式切换到慢速的字典模式，这对应于 `NormalizeProperties` 的调用。

**4. 元素的处理:**

```javascript
const arr = [1, 2, 3];
arr[3] = 4; // 添加新元素，可能触发元素存储的调整

const obj = { 0: 'a', 1: 'b' };
```

数组的元素添加和访问会涉及到 `GetElementsTransitionMap` 和 `AllocateStorageForMap` 等函数来管理元素的存储。

**5. 防止扩展和完整性级别:**

```javascript
const obj = { a: 1 };
Object.preventExtensions(obj); // 相当于调用 PreventExtensions
obj.b = 2; // 无法添加新属性

console.log(Object.isExtensible(obj)); // 相当于调用 IsExtensible

const sealedObj = { c: 3 };
Object.seal(sealedObj); // 阻止添加和删除属性，并标记为不可配置

const frozenObj = { d: 4 };
Object.freeze(frozenObj); // 阻止添加、删除和修改属性
console.log(Object.isFrozen(frozenObj)); // 相当于调用 TestIntegrityLevel
```

`Object.preventExtensions`、`Object.seal` 和 `Object.freeze` 直接对应于 `PreventExtensions` 等函数的实现。 `Object.isExtensible` 和 `Object.isFrozen` 则会调用相应的检查函数。

**6. 访问器属性:**

```javascript
const obj = {
  _value: 0,
  get value() { return this._value; }, // 对应 DefineOwnAccessorIgnoreAttributes
  set value(newValue) { this._value = newValue; } // 对应 DefineOwnAccessorIgnoreAttributes
};

console.log(obj.value); // 调用 getter
obj.value = 10; // 调用 setter
```

定义和访问访问器属性的行为由 `DefineOwnAccessorIgnoreAttributes` 和相关的代码处理。

**7. 原型优化:**

```javascript
function MyClass() {}
const proto = MyClass.prototype;
proto.method = function() {}; // V8 可能会优化 MyClass.prototype

const instance = new MyClass();
```

当一个对象被用作构造函数的原型时，V8 可能会调用 `OptimizeAsPrototype` 来优化其属性访问性能。

总而言之，`v8/src/objects/js-objects.cc` 的第 3 部分深入到 V8 引擎内部，实现了 JavaScript 对象属性管理的底层机制，确保了 JavaScript 语言的动态性和灵活性，并针对性能进行了优化。理解这部分代码有助于深入理解 JavaScript 对象的内部工作原理。

Prompt: 
```
这是目录为v8/src/objects/js-objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
property_count);
  }

  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate),
                                      isolate);
  for (InternalIndex i : InternalIndex::Range(real_size)) {
    PropertyDetails details = descs->GetDetails(i);
    Handle<Name> key(descs->GetKey(isolate, i), isolate);
    Handle<Object> value;
    if (details.location() == PropertyLocation::kField) {
      FieldIndex index = FieldIndex::ForDetails(*map, details);
      if (details.kind() == PropertyKind::kData) {
        value = handle(object->RawFastPropertyAt(isolate, index), isolate);
        if (details.representation().IsDouble()) {
          DCHECK(IsHeapNumber(*value, isolate));
          double old_value = Cast<HeapNumber>(value)->value();
          value = isolate->factory()->NewHeapNumber(old_value);
        }
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, details.kind());
        value = handle(object->RawFastPropertyAt(isolate, index), isolate);
      }

    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
      value = handle(descs->GetStrongValue(isolate, i), isolate);
    }
    DCHECK(!value.is_null());
    PropertyConstness constness = V8_DICT_PROPERTY_CONST_TRACKING_BOOL
                                      ? details.constness()
                                      : PropertyConstness::kMutable;
    PropertyDetails d(details.kind(), details.attributes(), constness);

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      ord_dictionary =
          SwissNameDictionary::Add(isolate, ord_dictionary, key, value, d);
    } else {
      dictionary = NameDictionary::Add(isolate, dictionary, key, value, d);
    }
  }

  if constexpr (!V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // Copy the next enumeration index from instance descriptor.
    dictionary->set_next_enumeration_index(real_size + 1);
    // TODO(pthier): Add flags to swiss dictionaries.
    dictionary->set_may_have_interesting_properties(
        map->may_have_interesting_properties());
  }

  // From here on we cannot fail and we shouldn't GC anymore.
  DisallowGarbageCollection no_gc;

  Heap* heap = isolate->heap();

  // Resize the object in the heap if necessary.
  int old_instance_size = map->instance_size();
  int new_instance_size = new_map->instance_size();
  int instance_size_delta = old_instance_size - new_instance_size;
  DCHECK_GE(instance_size_delta, 0);

  if (instance_size_delta > 0) {
    heap->NotifyObjectSizeChange(*object, old_instance_size, new_instance_size,
                                 ClearRecordedSlots::kYes);
  }

  // We are storing the new map using release store after creating a filler for
  // the left-over space to avoid races with the sweeper thread.
  object->set_map(isolate, *new_map, kReleaseStore);

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    object->SetProperties(*ord_dictionary);
  } else {
    object->SetProperties(*dictionary);
  }

  // Ensure that in-object space of slow-mode object does not contain random
  // garbage.
  int inobject_properties = new_map->GetInObjectProperties();
  if (inobject_properties) {
    for (int i = 0; i < inobject_properties; i++) {
      FieldIndex index = FieldIndex::ForPropertyIndex(*new_map, i);
      object->FastPropertyAtPut(index, Smi::zero());
    }
  }

#ifdef DEBUG
  if (v8_flags.trace_normalization) {
    StdoutStream os;
    os << "Object properties have been normalized:\n";
    Print(*object, os);
  }
#endif
}

}  // namespace

void JSObject::MigrateToMap(Isolate* isolate, DirectHandle<JSObject> object,
                            DirectHandle<Map> new_map,
                            int expected_additional_properties) {
  if (object->map(isolate) == *new_map) return;
  DirectHandle<Map> old_map(object->map(isolate), isolate);
  NotifyMapChange(old_map, new_map, isolate);

  if (old_map->is_dictionary_map()) {
    // For slow-to-fast migrations JSObject::MigrateSlowToFast()
    // must be used instead.
    CHECK(new_map->is_dictionary_map());

    // Slow-to-slow migration is trivial.
    object->set_map(isolate, *new_map, kReleaseStore);
  } else if (!new_map->is_dictionary_map()) {
    MigrateFastToFast(isolate, object, new_map);
    if (old_map->is_prototype_map()) {
      DCHECK(!old_map->is_stable());
      DCHECK(new_map->is_stable());
      DCHECK(new_map->owns_descriptors());
      DCHECK(old_map->owns_descriptors());
      // Transfer ownership to the new map. Keep the descriptor pointer of the
      // old map intact because the concurrent marker might be iterating the
      // object with the old map.
      old_map->set_owns_descriptors(false);
      DCHECK(old_map->is_abandoned_prototype_map());
      // Ensure that no transition was inserted for prototype migrations.
      DCHECK_EQ(0,
                TransitionsAccessor(isolate, *old_map).NumberOfTransitions());
      DCHECK(IsUndefined(new_map->GetBackPointer(isolate), isolate));
      DCHECK(object->map(isolate) != *old_map);
    }
  } else {
    MigrateFastToSlow(isolate, object, new_map, expected_additional_properties);
  }

  // Careful: Don't allocate here!
  // For some callers of this method, |object| might be in an inconsistent
  // state now: the new map might have a new elements_kind, but the object's
  // elements pointer hasn't been updated yet. Callers will fix this, but in
  // the meantime, (indirectly) calling JSObjectVerify() must be avoided.
  // When adding code here, add a DisallowGarbageCollection too.
}

void JSObject::ForceSetPrototype(Isolate* isolate,
                                 DirectHandle<JSObject> object,
                                 Handle<JSPrototype> proto) {
  // object.__proto__ = proto;
  Handle<Map> old_map = Handle<Map>(object->map(), isolate);
  DirectHandle<Map> new_map = Map::Copy(isolate, old_map, "ForceSetPrototype");
  Map::SetPrototype(isolate, new_map, proto);
  JSObject::MigrateToMap(isolate, object, new_map);
}

Maybe<InterceptorResult> JSObject::SetPropertyWithInterceptor(
    LookupIterator* it, Maybe<ShouldThrow> should_throw, Handle<Object> value) {
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  return SetPropertyWithInterceptorInternal(it, it->GetInterceptor(),
                                            should_throw, value);
}

Handle<Map> JSObject::GetElementsTransitionMap(DirectHandle<JSObject> object,
                                               ElementsKind to_kind) {
  Handle<Map> map(object->map(), object->GetIsolate());
  return Map::TransitionElementsTo(object->GetIsolate(), map, to_kind);
}

void JSObject::AllocateStorageForMap(Handle<JSObject> object, Handle<Map> map) {
  DCHECK(object->map()->GetInObjectProperties() ==
         map->GetInObjectProperties());
  ElementsKind obj_kind = object->map()->elements_kind();
  ElementsKind map_kind = map->elements_kind();
  Isolate* isolate = object->GetIsolate();
  if (map_kind != obj_kind) {
    ElementsKind to_kind = GetMoreGeneralElementsKind(map_kind, obj_kind);
    if (IsDictionaryElementsKind(obj_kind)) {
      to_kind = obj_kind;
    }
    if (IsDictionaryElementsKind(to_kind)) {
      NormalizeElements(object);
    } else {
      TransitionElementsKind(object, to_kind);
    }
    map = MapUpdater{isolate, map}.ReconfigureElementsKind(to_kind);
  }
  int number_of_fields = map->NumberOfFields(ConcurrencyMode::kSynchronous);
  int inobject = map->GetInObjectProperties();
  int unused = map->UnusedPropertyFields();
  int total_size = number_of_fields + unused;
  int external = total_size - inobject;
  // Allocate mutable double boxes if necessary. It is always necessary if we
  // have external properties, but is also necessary if we only have inobject
  // properties but don't unbox double fields.

  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);
  DirectHandle<FixedArray> storage =
      isolate->factory()->NewFixedArray(inobject);

  DirectHandle<PropertyArray> array =
      isolate->factory()->NewPropertyArray(external);

  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    Representation representation = details.representation();
    if (!representation.IsDouble()) continue;
    FieldIndex index = FieldIndex::ForDetails(*map, details);
    auto box = isolate->factory()->NewHeapNumberWithHoleNaN();
    if (index.is_inobject()) {
      storage->set(index.property_index(), *box);
    } else {
      array->set(index.outobject_array_index(), *box);
    }
  }

  object->SetProperties(*array);
  for (int i = 0; i < inobject; i++) {
    FieldIndex index = FieldIndex::ForPropertyIndex(*map, i);
    Tagged<Object> value = storage->get(i);
    object->FastPropertyAtPut(index, value);
  }
  object->set_map(isolate, *map, kReleaseStore);
}

void JSObject::MigrateInstance(Isolate* isolate,
                               DirectHandle<JSObject> object) {
  Handle<Map> original_map(object->map(), isolate);
  DirectHandle<Map> map = Map::Update(isolate, original_map);
  map->set_is_migration_target(true);
  JSObject::MigrateToMap(isolate, object, map);
  if (v8_flags.trace_migration) {
    object->PrintInstanceMigration(stdout, *original_map, *map);
  }
#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    object->JSObjectVerify(isolate);
  }
#endif
}

// static
bool JSObject::TryMigrateInstance(Isolate* isolate,
                                  DirectHandle<JSObject> object) {
  DisallowDeoptimization no_deoptimization(isolate);
  Handle<Map> original_map(object->map(), isolate);
  Handle<Map> new_map;
  if (!Map::TryUpdate(isolate, original_map).ToHandle(&new_map)) {
    return false;
  }
  JSObject::MigrateToMap(isolate, object, new_map);
  if (v8_flags.trace_migration && *original_map != object->map()) {
    object->PrintInstanceMigration(stdout, *original_map, object->map());
  }
#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    object->JSObjectVerify(isolate);
  }
#endif
  return true;
}

namespace {

bool TryFastAddDataProperty(Isolate* isolate, DirectHandle<JSObject> object,
                            DirectHandle<Name> name, DirectHandle<Object> value,
                            PropertyAttributes attributes) {
  DCHECK(IsUniqueName(*name));
  Tagged<Map> map =
      TransitionsAccessor(isolate, object->map())
          .SearchTransition(*name, PropertyKind::kData, attributes);
  if (map.is_null()) return false;
  DCHECK(!map->is_dictionary_map());

  Handle<Map> new_map = handle(map, isolate);
  if (map->is_deprecated()) {
    new_map = Map::Update(isolate, new_map);
    if (new_map->is_dictionary_map()) return false;
  }

  InternalIndex descriptor = new_map->LastAdded();
  new_map = Map::PrepareForDataProperty(isolate, new_map, descriptor,
                                        PropertyConstness::kConst, value);
  JSObject::MigrateToMap(isolate, object, new_map);
  // TODO(leszeks): Avoid re-loading the property details, which we already
  // loaded in PrepareForDataProperty.
  object->WriteToField(descriptor,
                       new_map->instance_descriptors()->GetDetails(descriptor),
                       *value);
  return true;
}

}  // namespace

void JSObject::AddProperty(Isolate* isolate, Handle<JSObject> object,
                           Handle<Name> name, DirectHandle<Object> value,
                           PropertyAttributes attributes) {
  name = isolate->factory()->InternalizeName(name);
  if (TryFastAddDataProperty(isolate, object, name, value, attributes)) {
    return;
  }

  LookupIterator it(isolate, object, name, object,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_NE(LookupIterator::ACCESS_CHECK, it.state());
#ifdef DEBUG
  uint32_t index;
  DCHECK(!IsJSProxy(*object));
  DCHECK(!IsWasmObject(*object));
  DCHECK(!name->AsArrayIndex(&index));
  Maybe<PropertyAttributes> maybe = GetPropertyAttributes(&it);
  DCHECK(maybe.IsJust());
  DCHECK(!it.IsFound());
  DCHECK(object->map()->is_extensible() || name->IsPrivate());
#endif
  CHECK(Object::AddDataProperty(&it, value, attributes,
                                Just(ShouldThrow::kThrowOnError),
                                StoreOrigin::kNamed)
            .IsJust());
}

void JSObject::AddProperty(Isolate* isolate, Handle<JSObject> object,
                           const char* name, DirectHandle<Object> value,
                           PropertyAttributes attributes) {
  JSObject::AddProperty(isolate, object,
                        isolate->factory()->InternalizeUtf8String(name), value,
                        attributes);
}

// Reconfigures a property to a data property with attributes, even if it is not
// reconfigurable.
// Requires a LookupIterator that does not look at the prototype chain beyond
// hidden prototypes.
MaybeHandle<Object> JSObject::DefineOwnPropertyIgnoreAttributes(
    LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
    AccessorInfoHandling handling, EnforceDefineSemantics semantics) {
  MAYBE_RETURN_NULL(DefineOwnPropertyIgnoreAttributes(
      it, value, attributes, Just(ShouldThrow::kThrowOnError), handling,
      semantics));
  return value;
}

Maybe<bool> JSObject::DefineOwnPropertyIgnoreAttributes(
    LookupIterator* it, Handle<Object> value, PropertyAttributes attributes,
    Maybe<ShouldThrow> should_throw, AccessorInfoHandling handling,
    EnforceDefineSemantics semantics, StoreOrigin store_origin) {
  it->UpdateProtector();

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::JSPROXY:
      case LookupIterator::WASM_OBJECT:
      case LookupIterator::TRANSITION:
        UNREACHABLE();

      case LookupIterator::ACCESS_CHECK:
        if (!it->HasAccess()) {
          Isolate* isolate = it->isolate();
          RETURN_ON_EXCEPTION_VALUE(
              isolate,
              isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()),
              Nothing<bool>());
          UNREACHABLE();
        }
        continue;

      // If there's an interceptor, try to store the property with the
      // interceptor.
      // In case of success, the attributes will have been reset to the default
      // attributes of the interceptor, rather than the incoming attributes.
      //
      // TODO(verwaest): JSProxy afterwards verify the attributes that the
      // JSProxy claims it has, and verifies that they are compatible. If not,
      // they throw. Here we should do the same.
      case LookupIterator::INTERCEPTOR: {
        InterceptorResult result;
        if (semantics == EnforceDefineSemantics::kDefine) {
          PropertyDescriptor descriptor;
          descriptor.set_configurable((attributes & DONT_DELETE) != 0);
          descriptor.set_enumerable((attributes & DONT_ENUM) != 0);
          descriptor.set_writable((attributes & READ_ONLY) != 0);
          descriptor.set_value(Cast<JSAny>(value));
          if (!DefinePropertyWithInterceptorInternal(it, it->GetInterceptor(),
                                                     should_throw, &descriptor)
                   .To(&result)) {
            // An exception was thrown in the interceptor. Propagate.
            return Nothing<bool>();
          }
        } else {
          DCHECK_EQ(semantics, EnforceDefineSemantics::kSet);
          if (handling == DONT_FORCE_FIELD) {
            if (!JSObject::SetPropertyWithInterceptor(it, should_throw, value)
                     .To(&result)) {
              // An exception was thrown in the interceptor. Propagate.
              return Nothing<bool>();
            }
          } else {
            result = InterceptorResult::kNotIntercepted;
          }
        }
        switch (result) {
          case InterceptorResult::kFalse:
            return Just(false);
          case InterceptorResult::kTrue:
            return Just(true);
          case InterceptorResult::kNotIntercepted:
            // Proceed lookup.
            break;
        }

        if (semantics == EnforceDefineSemantics::kDefine) {
          it->Restart();
          Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
              it->isolate(), it, value, should_throw);
          if (can_define.IsNothing() || !can_define.FromJust()) {
            return can_define;
          }
        }

        // The interceptor declined to handle the operation, so proceed defining
        // own property without the interceptor.
        Isolate* isolate = it->isolate();
        Handle<JSAny> receiver = it->GetReceiver();
        LookupIterator own_lookup(isolate, receiver, it->GetKey(),
                                  LookupIterator::OWN_SKIP_INTERCEPTOR);
        return JSObject::DefineOwnPropertyIgnoreAttributes(
            &own_lookup, value, attributes, should_throw, handling, semantics,
            store_origin);
      }

      case LookupIterator::ACCESSOR: {
        Handle<Object> accessors = it->GetAccessors();

        // Special handling for AccessorInfo, which behaves like a data
        // property.
        if (IsAccessorInfo(*accessors) && handling == DONT_FORCE_FIELD) {
          PropertyAttributes current_attributes = it->property_attributes();
          // Ensure the context isn't changed after calling into accessors.
          AssertNoContextChange ncc(it->isolate());

          // Update the attributes before calling the setter. The setter may
          // later change the shape of the property.
          if (current_attributes != attributes) {
            it->TransitionToAccessorPair(accessors, attributes);
          }

          return Object::SetPropertyWithAccessor(it, value, should_throw);
        }

        it->ReconfigureDataProperty(value, attributes);
        return Just(true);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return Object::RedefineIncompatibleProperty(
            it->isolate(), it->GetName(), value, should_throw);

      case LookupIterator::DATA: {
        // Regular property update if the attributes match.
        if (it->property_attributes() == attributes) {
          return Object::SetDataProperty(it, value);
        }

        // The non-matching attribute case for JSTypedArrays has already been
        // handled by JSTypedArray::DefineOwnProperty.
        DCHECK(!it->IsElement() ||
               !Cast<JSObject>(it->GetReceiver())
                    ->HasTypedArrayOrRabGsabTypedArrayElements());
        // Reconfigure the data property if the attributes mismatch.
        it->ReconfigureDataProperty(value, attributes);

        return Just(true);
      }

      case LookupIterator::NOT_FOUND:
        return Object::AddDataProperty(it, value, attributes, should_throw,
                                       store_origin, semantics);
    }
    UNREACHABLE();
  }
}

MaybeHandle<Object> JSObject::SetOwnPropertyIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, Handle<Object> value,
    PropertyAttributes attributes) {
  DCHECK(!IsTheHole(*value));
  LookupIterator it(object->GetIsolate(), object, name, object,
                    LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

MaybeHandle<Object> JSObject::SetOwnElementIgnoreAttributes(
    Handle<JSObject> object, size_t index, Handle<Object> value,
    PropertyAttributes attributes) {
  DCHECK(!IsJSTypedArray(*object));
  Isolate* isolate = object->GetIsolate();
  LookupIterator it(isolate, object, index, object, LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

MaybeHandle<Object> JSObject::DefinePropertyOrElementIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, Handle<Object> value,
    PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);
  return DefineOwnPropertyIgnoreAttributes(&it, value, attributes);
}

Maybe<PropertyAttributes> JSObject::GetPropertyAttributesWithInterceptor(
    LookupIterator* it) {
  return GetPropertyAttributesWithInterceptorInternal(it, it->GetInterceptor());
}

void JSObject::NormalizeProperties(Isolate* isolate,
                                   DirectHandle<JSObject> object,
                                   PropertyNormalizationMode mode,
                                   int expected_additional_properties,
                                   bool use_cache, const char* reason) {
  if (!object->HasFastProperties()) return;

  Handle<Map> map(object->map(), isolate);
  DirectHandle<Map> new_map = Map::Normalize(isolate, map, map->elements_kind(),
                                             {}, mode, use_cache, reason);

  JSObject::MigrateToMap(isolate, object, new_map,
                         expected_additional_properties);
}

void JSObject::MigrateSlowToFast(DirectHandle<JSObject> object,
                                 int unused_property_fields,
                                 const char* reason) {
  if (object->HasFastProperties()) return;
  DCHECK(!IsJSGlobalObject(*object));
  Isolate* isolate = object->GetIsolate();
  Factory* factory = isolate->factory();

  Handle<NameDictionary> dictionary;
  DirectHandle<SwissNameDictionary> swiss_dictionary;
  int number_of_elements;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    swiss_dictionary = handle(object->property_dictionary_swiss(), isolate);
    number_of_elements = swiss_dictionary->NumberOfElements();
  } else {
    dictionary = handle(object->property_dictionary(), isolate);
    number_of_elements = dictionary->NumberOfElements();
  }

  // Make sure we preserve dictionary representation if there are too many
  // descriptors.
  if (number_of_elements > kMaxNumberOfDescriptors) return;

  DirectHandle<FixedArray> iteration_order;
  int iteration_length;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // |iteration_order| remains empty handle, we don't need it.
    iteration_length = swiss_dictionary->UsedCapacity();
  } else {
    iteration_order = NameDictionary::IterationIndices(isolate, dictionary);
    iteration_length = dictionary->NumberOfElements();
  }

  int number_of_fields = 0;

  // Compute the length of the instance descriptor.
  ReadOnlyRoots roots(isolate);
  for (int i = 0; i < iteration_length; i++) {
    PropertyKind kind;
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      InternalIndex index(swiss_dictionary->EntryForEnumerationIndex(i));
      Tagged<Object> key = swiss_dictionary->KeyAt(index);
      if (!SwissNameDictionary::IsKey(roots, key)) {
        // Ignore deleted entries.
        continue;
      }
      kind = swiss_dictionary->DetailsAt(index).kind();
    } else {
      InternalIndex index(Smi::ToInt(iteration_order->get(i)));
      DCHECK(dictionary->IsKey(roots, dictionary->KeyAt(isolate, index)));
      kind = dictionary->DetailsAt(index).kind();
    }

    if (kind == PropertyKind::kData) {
      number_of_fields += 1;
    }
  }

  Handle<Map> old_map(object->map(), isolate);

  int inobject_props = old_map->GetInObjectProperties();

  // Allocate new map.
  Handle<Map> new_map = Map::CopyDropDescriptors(isolate, old_map);
  // We should not only set this bit if we need to. We should not retain the
  // old bit because turning a map into dictionary always sets this bit.
  new_map->set_may_have_interesting_properties(
      new_map->has_named_interceptor() || new_map->is_access_check_needed());
  new_map->set_is_dictionary_map(false);

  NotifyMapChange(old_map, new_map, isolate);

  if (number_of_elements == 0) {
    DisallowGarbageCollection no_gc;
    DCHECK_LE(unused_property_fields, inobject_props);
    // Transform the object.
    new_map->SetInObjectUnusedPropertyFields(inobject_props);
    object->set_map(isolate, *new_map, kReleaseStore);
    object->SetProperties(ReadOnlyRoots(isolate).empty_fixed_array());
    // Check that it really works.
    DCHECK(object->HasFastProperties());
    if (v8_flags.log_maps) {
      LOG(isolate, MapEvent("SlowToFast", old_map, new_map, reason));
    }
    return;
  }

  // Allocate the instance descriptor.
  DirectHandle<DescriptorArray> descriptors =
      DescriptorArray::Allocate(isolate, number_of_elements, 0);

  int number_of_allocated_fields =
      number_of_fields + unused_property_fields - inobject_props;
  if (number_of_allocated_fields < 0) {
    // There is enough inobject space for all fields (including unused).
    number_of_allocated_fields = 0;
    unused_property_fields = inobject_props - number_of_fields;
  }

  // Allocate the property array for the fields.
  DirectHandle<PropertyArray> fields =
      factory->NewPropertyArray(number_of_allocated_fields);

  bool is_transitionable_elements_kind =
      IsTransitionableFastElementsKind(old_map->elements_kind());

  // Fill in the instance descriptor and the fields.
  int current_offset = 0;
  int descriptor_index = 0;
  for (int i = 0; i < iteration_length; i++) {
    Tagged<Name> k;
    Tagged<Object> value;
    PropertyDetails details = PropertyDetails::Empty();

    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      InternalIndex index(swiss_dictionary->EntryForEnumerationIndex(i));
      Tagged<Object> key_obj = swiss_dictionary->KeyAt(index);
      if (!SwissNameDictionary::IsKey(roots, key_obj)) {
        continue;
      }
      k = Cast<Name>(key_obj);

      value = swiss_dictionary->ValueAt(index);
      details = swiss_dictionary->DetailsAt(index);
    } else {
      InternalIndex index(Smi::ToInt(iteration_order->get(i)));
      k = dictionary->NameAt(index);

      value = dictionary->ValueAt(index);
      details = dictionary->DetailsAt(index);
    }

    // Dictionary keys are internalized upon insertion.
    // TODO(jkummerow): Turn this into a DCHECK if it's not hit in the wild.
    CHECK(IsUniqueName(k));
    Handle<Name> key(k, isolate);

    // Properly mark the {new_map} if the {key} is an "interesting symbol".
    if (key->IsInteresting(isolate)) {
      new_map->set_may_have_interesting_properties(true);
    }

    DCHECK_EQ(PropertyLocation::kField, details.location());
    DCHECK_IMPLIES(!V8_DICT_PROPERTY_CONST_TRACKING_BOOL,
                   details.constness() == PropertyConstness::kMutable);

    Descriptor d;
    if (details.kind() == PropertyKind::kData) {
      // Ensure that we make constant field only when elements kind is not
      // transitionable.
      PropertyConstness constness = is_transitionable_elements_kind
                                        ? PropertyConstness::kMutable
                                        : PropertyConstness::kConst;
      // TODO(v8:11248): Consider always setting constness to kMutable
      // once all prototypes stay in dictionary mode and we are not interested
      // in tracking constness for fast mode properties anymore.

      d = Descriptor::DataField(
          key, current_offset, details.attributes(), constness,
          // TODO(verwaest): value->OptimalRepresentation();
          Representation::Tagged(), MaybeObjectHandle(FieldType::Any(isolate)));
    } else {
      DCHECK_EQ(PropertyKind::kAccessor, details.kind());
      d = Descriptor::AccessorConstant(key, handle(value, isolate),
                                       details.attributes());
    }
    details = d.GetDetails();
    if (details.location() == PropertyLocation::kField) {
      if (current_offset < inobject_props) {
        object->InObjectPropertyAtPut(current_offset, value,
                                      UPDATE_WRITE_BARRIER);
      } else {
        int offset = current_offset - inobject_props;
        fields->set(offset, value);
      }
      current_offset += details.field_width_in_words();
    }
    descriptors->Set(InternalIndex(descriptor_index++), &d);
  }
  DCHECK_EQ(current_offset, number_of_fields);
  DCHECK_EQ(descriptor_index, number_of_elements);

  descriptors->Sort();

  DisallowGarbageCollection no_gc;
  new_map->InitializeDescriptors(isolate, *descriptors);
  if (number_of_allocated_fields == 0) {
    new_map->SetInObjectUnusedPropertyFields(unused_property_fields);
  } else {
    new_map->SetOutOfObjectUnusedPropertyFields(unused_property_fields);
  }

  if (v8_flags.log_maps) {
    LOG(isolate, MapEvent("SlowToFast", old_map, new_map, reason));
  }
  // Transform the object.
  object->set_map(isolate, *new_map, kReleaseStore);

  object->SetProperties(*fields);
  DCHECK(IsJSObject(*object));

  // Check that it really works.
  DCHECK(object->HasFastProperties());
}

void JSObject::RequireSlowElements(Tagged<NumberDictionary> dictionary) {
  DCHECK_NE(dictionary,
            ReadOnlyRoots(GetIsolate()).empty_slow_element_dictionary());
  if (dictionary->requires_slow_elements()) return;
  dictionary->set_requires_slow_elements();
  if (map()->is_prototype_map()) {
    // If this object is a prototype (the callee will check), invalidate any
    // prototype chains involving it.
    InvalidatePrototypeChains(map());
  }
}

Handle<NumberDictionary> JSObject::NormalizeElements(Handle<JSObject> object) {
  DCHECK(!object->HasTypedArrayOrRabGsabTypedArrayElements());
  Isolate* isolate = object->GetIsolate();
  bool is_sloppy_arguments = object->HasSloppyArgumentsElements();
  {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements = object->elements();

    if (is_sloppy_arguments) {
      elements = Cast<SloppyArgumentsElements>(elements)->arguments();
    }

    if (IsNumberDictionary(elements)) {
      return handle(Cast<NumberDictionary>(elements), isolate);
    }
  }

  DCHECK(object->HasSmiOrObjectElements() || object->HasDoubleElements() ||
         object->HasFastArgumentsElements() ||
         object->HasFastStringWrapperElements() ||
         object->HasSealedElements() || object->HasNonextensibleElements());

  Handle<NumberDictionary> dictionary =
      object->GetElementsAccessor()->Normalize(object);

  // Switch to using the dictionary as the backing storage for elements.
  ElementsKind target_kind =
      is_sloppy_arguments                      ? SLOW_SLOPPY_ARGUMENTS_ELEMENTS
      : object->HasFastStringWrapperElements() ? SLOW_STRING_WRAPPER_ELEMENTS
                                               : DICTIONARY_ELEMENTS;
  DirectHandle<Map> new_map =
      JSObject::GetElementsTransitionMap(object, target_kind);
  // Set the new map first to satify the elements type assert in set_elements().
  JSObject::MigrateToMap(isolate, object, new_map);

  if (is_sloppy_arguments) {
    Cast<SloppyArgumentsElements>(object->elements())
        ->set_arguments(*dictionary);
  } else {
    object->set_elements(*dictionary);
  }

#ifdef DEBUG
  if (v8_flags.trace_normalization) {
    StdoutStream os;
    os << "Object elements have been normalized:\n";
    Print(*object, os);
  }
#endif

  DCHECK(object->HasDictionaryElements() ||
         object->HasSlowArgumentsElements() ||
         object->HasSlowStringWrapperElements());
  return dictionary;
}

Maybe<InterceptorResult> JSObject::DeletePropertyWithInterceptor(
    LookupIterator* it, ShouldThrow should_throw) {
  Isolate* isolate = it->isolate();
  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(isolate);

  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  Handle<InterceptorInfo> interceptor(it->GetInterceptor());
  if (IsUndefined(interceptor->deleter(), isolate)) {
    return Just(InterceptorResult::kNotIntercepted);
  }
  DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
  Handle<Object> receiver = it->GetReceiver();
  if (!IsJSReceiver(*receiver)) {
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, receiver,
                                     Object::ConvertReceiver(isolate, receiver),
                                     Nothing<InterceptorResult>());
  }

  PropertyCallbackArguments args(isolate, interceptor->data(), *receiver,
                                 *holder, Just(should_throw));

  v8::Intercepted intercepted =
      it->IsElement(*holder)
          ? args.CallIndexedDeleter(interceptor, it->array_index())
          : args.CallNamedDeleter(interceptor, it->name());

  return args.GetBooleanReturnValue(intercepted, "Deleter");
}

Maybe<bool> JSObject::CreateDataProperty(Isolate* isolate,
                                         Handle<JSObject> object,
                                         PropertyKey key, Handle<Object> value,
                                         Maybe<ShouldThrow> should_throw) {
  if (!key.is_element()) {
    if (TryFastAddDataProperty(isolate, object, key.name(), value, NONE)) {
      return Just(true);
    }
  }

  LookupIterator it(isolate, object, key, LookupIterator::OWN);
  Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
      isolate, &it, value, should_throw);
  if (can_define.IsNothing() || !can_define.FromJust()) {
    return can_define;
  }

  RETURN_ON_EXCEPTION_VALUE(isolate,
                            DefineOwnPropertyIgnoreAttributes(&it, value, NONE),
                            Nothing<bool>());

  return Just(true);
}

namespace {

template <typename Dictionary>
bool TestDictionaryPropertiesIntegrityLevel(Tagged<Dictionary> dict,
                                            ReadOnlyRoots roots,
                                            PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);

  for (InternalIndex i : dict->IterateEntries()) {
    Tagged<Object> key;
    if (!dict->ToKey(roots, i, &key)) continue;
    if (Object::FilterKey(key, ALL_PROPERTIES)) continue;
    PropertyDetails details = dict->DetailsAt(i);
    if (details.IsConfigurable()) return false;
    if (level == FROZEN && details.kind() == PropertyKind::kData &&
        !details.IsReadOnly()) {
      return false;
    }
  }
  return true;
}

bool TestFastPropertiesIntegrityLevel(Tagged<Map> map,
                                      PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);
  DCHECK(!IsCustomElementsReceiverMap(map));
  DCHECK(!map->is_dictionary_map());

  Tagged<DescriptorArray> descriptors = map->instance_descriptors();
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    if (descriptors->GetKey(i)->IsPrivate()) continue;
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.IsConfigurable()) return false;
    if (level == FROZEN && details.kind() == PropertyKind::kData &&
        !details.IsReadOnly()) {
      return false;
    }
  }
  return true;
}

bool TestPropertiesIntegrityLevel(Tagged<JSObject> object,
                                  PropertyAttributes level) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));

  if (object->HasFastProperties()) {
    return TestFastPropertiesIntegrityLevel(object->map(), level);
  }

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return TestDictionaryPropertiesIntegrityLevel(
        object->property_dictionary_swiss(), object->GetReadOnlyRoots(), level);
  } else {
    return TestDictionaryPropertiesIntegrityLevel(
        object->property_dictionary(), object->GetReadOnlyRoots(), level);
  }
}

bool TestElementsIntegrityLevel(Isolate* isolate, Tagged<JSObject> object,
                                PropertyAttributes level) {
  DCHECK(!object->HasSloppyArgumentsElements());

  ElementsKind kind = object->GetElementsKind();

  if (IsDictionaryElementsKind(kind)) {
    return TestDictionaryPropertiesIntegrityLevel(
        Cast<NumberDictionary>(object->elements()), object->GetReadOnlyRoots(),
        level);
  }
  if (IsTypedArrayOrRabGsabTypedArrayElementsKind(kind)) {
    if (level == FROZEN && Cast<JSArrayBufferView>(object)->byte_length() > 0) {
      return false;  // TypedArrays with elements can't be frozen.
    }
    return TestPropertiesIntegrityLevel(object, level);
  }
  if (IsFrozenElementsKind(kind)) return true;
  if (IsSealedElementsKind(kind) && level != FROZEN) return true;
  if (IsNonextensibleElementsKind(kind) && level == NONE) return true;

  ElementsAccessor* accessor = ElementsAccessor::ForKind(kind);
  // Only DICTIONARY_ELEMENTS and SLOW_SLOPPY_ARGUMENTS_ELEMENTS have
  // PropertyAttributes so just test if empty
  return accessor->NumberOfElements(isolate, object) == 0;
}

bool FastTestIntegrityLevel(Isolate* isolate, Tagged<JSObject> object,
                            PropertyAttributes level) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));

  return !object->map()->is_extensible() &&
         TestElementsIntegrityLevel(isolate, object, level) &&
         TestPropertiesIntegrityLevel(object, level);
}

}  // namespace

Maybe<bool> JSObject::TestIntegrityLevel(Isolate* isolate,
                                         Handle<JSObject> object,
                                         IntegrityLevel level) {
  if (!IsCustomElementsReceiverMap(object->map()) &&
      !object->HasSloppyArgumentsElements()) {
    return Just(FastTestIntegrityLevel(isolate, *object, level));
  }
  return GenericTestIntegrityLevel(isolate, Cast<JSReceiver>(object), level);
}

Maybe<bool> JSObject::PreventExtensions(Isolate* isolate,
                                        Handle<JSObject> object,
                                        ShouldThrow should_throw) {
  if (!object->HasSloppyArgumentsElements()) {
    return PreventExtensionsWithTransition<NONE>(isolate, object, should_throw);
  }

  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(object),
                              Nothing<bool>());
    UNREACHABLE();
  }

  if (!object->map()->is_extensible()) return Just(true);

  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, object);
    if (iter.IsAtEnd()) return Just(true);
    DCHECK(IsJSGlobalObject(*PrototypeIterator::GetCurrent(iter)));
    return PreventExtensions(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), should_throw);
  }

  if (object->map()->has_named_interceptor() ||
      object->map()->has_indexed_interceptor()) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kCannotPreventExt));
  }

  DCHECK(!object->HasTypedArrayOrRabGsabTypedArrayElements());

  // Normalize fast elements.
  DirectHandle<NumberDictionary> dictionary = NormalizeElements(object);
  DCHECK(object->HasDictionaryElements() || object->HasSlowArgumentsElements());

  // Make sure that we never go back to fast case.
  if (*dictionary != ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
    object->RequireSlowElements(*dictionary);
  }

  // Do a map transition, other objects with this map may still
  // be extensible.
  // TODO(adamk): Extend the NormalizedMapCache to handle non-extensible maps.
  DirectHandle<Map> new_map =
      Map::Copy(isolate, handle(object->map(), isolate), "PreventExtensions");

  new_map->set_is_extensible(false);
  JSObject::MigrateToMap(isolate, object, new_map);
  DCHECK(!object->map()->is_extensible());

  return Just(true);
}

bool JSObject::IsExtensible(Isolate* isolate, Handle<JSObject> object) {
  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    return true;
  }
  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, *object);
    if (iter.IsAtEnd()) return false;
    DCHECK(IsJSGlobalObject(iter.GetCurrent()));
    return iter.GetCurrent<JSObject>()->map()->is_extensible();
  }
  return object->map()->is_extensible();
}

// static
MaybeHandle<Object> JSObject::ReadFromOptionsBag(Handle<Object> options,
                                                 Handle<String> option_name,
                                                 Isolate* isolate) {
  if (IsJSReceiver(*options)) {
    Handle<JSReceiver> js_options = Cast<JSReceiver>(options);
    return JSObject::GetProperty(isolate, js_options, option_name);
  }
  return MaybeHandle<Object>(isolate->factory()->undefined_value());
}

template <typename Dictionary>
void JSObject::ApplyAttributesToDictionary(
    Isolate* isolate, ReadOnlyRoots roots, Handle<Dictionary> dictionary,
    const PropertyAttributes attributes) {
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> k;
    if (!dictionary->ToKey(roots, i, &k)) continue;
    if (Object::FilterKey(k, ALL_PROPERTIES)) continue;
    PropertyDetails details = dictionary->DetailsAt(i);
    int attrs = attributes;
    // READ_ONLY is an invalid attribute for JS setters/getters.
    if ((attributes & READ_ONLY) && details.kind() == PropertyKind::kAccessor) {
      Tagged<Object> v = dictionary->ValueAt(i);
      if (IsAccessorPair(v)) attrs &= ~READ_ONLY;
    }
    details = details.CopyAddAttributes(PropertyAttributesFromInt(attrs));
    dictionary->DetailsAtPut(i, details);
  }
}

template void JSObject::ApplyAttributesToDictionary(
    Isolate* isolate, ReadOnlyRoots roots, Handle<NumberDictionary> dictionary,
    const PropertyAttributes attributes);

Handle<NumberDictionary> CreateElementDictionary(Isolate* isolate,
                                                 Handle<JSObject> object) {
  Handle<NumberDictionary> new_element_dictionary;
  if (!object->HasTypedArrayOrRabGsabTypedArrayElements() &&
      !object->HasDictionaryElements() &&
      !object->HasSlowStringWrapperElements()) {
    int length = IsJSArray(*object)
                     ? Smi::ToInt(Cast<JSArray>(object)->length())
                     : object->elements()->length();
    new_element_dictionary =
        length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                    : object->GetElementsAccessor()->Normalize(object);
  }
  return new_element_dictionary;
}

template <PropertyAttributes attrs>
Maybe<bool> JSObject::PreventExtensionsWithTransition(
    Isolate* isolate, Handle<JSObject> object, ShouldThrow should_throw) {
  static_assert(attrs == NONE || attrs == SEALED || attrs == FROZEN);

  // Sealing/freezing sloppy arguments or namespace objects should be handled
  // elsewhere.
  DCHECK(!object->HasSloppyArgumentsElements());
  DCHECK_IMPLIES(IsJSModuleNamespace(*object), attrs == NONE);

  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(object),
                              Nothing<bool>());
    UNREACHABLE();
  }

  if (attrs == NONE && !object->map()->is_extensible()) {
    return Just(true);
  }

  {
    ElementsKind old_elements_kind = object->map()->elements_kind();
    if (IsFrozenElementsKind(old_elements_kind)) return Just(true);
    if (attrs != FROZEN && IsSealedElementsKind(old_elements_kind)) {
      return Just(true);
    }
  }

  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, object);
    if (iter.IsAtEnd()) return Just(true);
    DCHECK(IsJSGlobalObject(*PrototypeIterator::GetCurrent(iter)));
    return PreventExtensionsWithTransition<attrs>(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), should_throw);
  }

  // Shared objects are designed to have fixed layout, i.e. their maps are
  // effectively immutable. They are constructed seal, but the semantics of
  // ordinary ECMAScript objects allow sealed to be upgraded to frozen. This
  // upgrade violates the fixed layout invariant and is disallowed.
  if (IsAlwaysSharedSpaceJSObject(*object)) {
    DCHECK(FastTestIntegrityLevel(isolate, *object, SEALED));
    if (attrs != FROZEN) return Just(true);
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kCannotFreeze));
  }

  if (object->map()->has_named_interceptor() ||
      object->map()->has_indexed_interceptor() ||
      (object->HasTypedArrayOrRabGsabTypedArrayElements() &&
       Cast<JSTypedArray>(*object)->IsVariableLength())) {
    MessageTemplate message = MessageTemplate::kNone;
    switch (attrs) {
      case NONE:
        message = MessageTemplate::kCannotPreventExt;
        break;

      case SEALED:
        message = MessageTemplate::kCannotSeal;
        break;

      case FROZEN:
        message = MessageTemplate::kCannotFreeze;
        break;
    }
    RETURN_FAILURE(isolate, should_throw, NewTypeError(message));
  }

  Handle<Symbol> transition_marker;
  if (attrs == NONE) {
    transition_marker = isolate->factory()->nonextensible_symbol();
  } else if (attrs == SEALED) {
    transition_marker = isolate->factory()->sealed_symbol();
  } else {
    DCHECK(attrs == FROZEN);
    transition_marker = isolate->factory()->frozen_symbol();
  }

  // Currently, there are only have sealed/frozen Object element kinds and
  // Map::MigrateToMap doesn't handle properties' attributes reconfiguring and
  // elements kind change in one go. If seal or freeze with Smi or Double
  // elements kind, we will transition to Object elements kind first to make
  // sure of valid element access.
  if (v8_flags.enable_sealed_frozen_elements_kind) {
    switch (object->map()->elements_kind()) {
      case PACKED_SMI_ELEMENTS:
      case PACKED_DOUBLE_ELEMENTS:
        JSObject::TransitionElementsKind(object, PACKED_ELEMENTS);
        break;
      case HOLEY_SMI_ELEMENTS:
      case HOLEY_DOUBLE_ELEMENTS:
        JSObject::TransitionElementsKind(object, HOLEY_ELEMENTS);
        break;
      default:
        break;
    }
  }

  // Make sure we only use this element dictionary in case we can't transition
  // to sealed, frozen elements kind.
  Handle<NumberDictionary> new_element_dictionary;

  Handle<Map> old_map(object->map(), isolate);
  old_map = Map::Update(isolate, old_map);
  Handle<Map> transition_map;
  MaybeHandle<Map> maybe_transition_map =
      TransitionsAccessor::SearchSpecial(isolate, old_map, *transition_marker);
  if (maybe_transition_map.ToHandle(&transition_map)) {
    DCHECK(transition_map->has_dictionary_elements() ||
           transition_map->has_typed_array_or_rab_gsab_typed_array_elements() ||
           transition_map->elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS ||
           transition_map->has_any_nonextensible_elements());
    DCHECK(!transition_map->is_extensible());
    if (!transition_map->has_any_nonextensible_elements()) {
      new_element_dictionary = CreateElementDictionary(isolate, object);
    }
    JSObject::MigrateToMap(isolate, object, transition_map);
  } else if (TransitionsAccessor::CanHaveMoreTransitions(isolate, old_map)) {
    // Create a new descriptor array with the appropriate property attributes
    DirectHandle<Map> new_map = Map::CopyForPreventExtensions(
        isolate, old_map, attrs, transition_marker, "CopyForPreventExtensions");
    if (!new_map->has_any_nonextensible_elements()) {
      new_element_dictionary = CreateElementDictionary(isolate, object);
    }
    JSObject::MigrateToMap(isolate, object, new_map);
  } else {
    DCHECK(old_map->is_dictionary_map() || !old_map->is_prototype_map());
    // Slow path: need to normalize properties for safety
    NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                        "SlowPreventExtensions");

    // Create a new map, since other objects with this map may be extensible.
    // TODO(adamk): Extend the NormalizedMapCache to handle non-extensible maps.
    DirectHandle<Map> new_map =
        Map::Copy(isolate, handle(object->map(), isolate),
                  "SlowCopyForPreventExtensions");
    new_map->set_is_extensible(false);
    new_element_dictionary = CreateElementDictionary(isolate, object);
    if (!new_element_dictionary.is_null()) {
      ElementsKind new_kind =
          IsStringWrapperElementsKind(old_map->elements_kind())
              ? SLOW_STRING_WRAPPER_ELEMENTS
              : DICTIONARY_ELEMENTS;
      new_map->set_elements_kind(new_kind);
    }
    JSObject::MigrateToMap(isolate, object, new_map);

    if (attrs != NONE) {
      ReadOnlyRoots roots(isolate);
      if (IsJSGlobalObject(*object)) {
        Handle<GlobalDictionary> dictionary(
            Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
            isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        Handle<SwissNameDictionary> dictionary(
            object->property_dictionary_swiss(), isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      } else {
        Handle<NameDictionary> dictionary(object->property_dictionary(),
                                          isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      }
    }
  }

  if (object->map()->has_any_nonextensible_elements()) {
    DCHECK(new_element_dictionary.is_null());
    return Just(true);
  }

  // Both seal and preventExtensions always go through without modifications to
  // typed array elements if the typed array is fixed length. Freeze works only
  // if there are no actual elements.
  if (object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    DCHECK(new_element_dictionary.is_null());
    if (attrs == FROZEN && Cast<JSTypedArray>(*object)->GetLength() > 0) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kCannotFreezeArrayBufferView));
      return Nothing<bool>();
    }
    return Just(true);
  }

  DCHECK(object->map()->has_dictionary_elements() ||
         object->map()->elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS);
  if (!new_element_dictionary.is_null()) {
    object->set_elements(*new_element_dictionary);
  }

  if (object->elements() !=
      ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
    Handle<NumberDictionary> dictionary(object->element_dictionary(), isolate);
    // Make sure we never go back to the fast case
    object->RequireSlowElements(*dictionary);
    if (attrs != NONE) {
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary, attrs);
    }
  }

  return Just(true);
}

Handle<JSAny> JSObject::FastPropertyAt(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Representation representation,
                                       FieldIndex index) {
  Handle<JSAny> raw_value(object->RawFastPropertyAt(index), isolate);
  return Object::WrapForRead(isolate, raw_value, representation);
}

Handle<JSAny> JSObject::FastPropertyAt(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Representation representation,
                                       FieldIndex index, SeqCstAccessTag tag) {
  Handle<JSAny> raw_value(object->RawFastPropertyAt(index, tag), isolate);
  return Object::WrapForRead(isolate, raw_value, representation);
}

// static
Handle<Object> JSObject::DictionaryPropertyAt(Isolate* isolate,
                                              DirectHandle<JSObject> object,
                                              InternalIndex dict_index) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Tagged<SwissNameDictionary> dict = object->property_dictionary_swiss();
    return handle(dict->ValueAt(dict_index), isolate);
  } else {
    Tagged<NameDictionary> dict = object->property_dictionary();
    return handle(dict->ValueAt(dict_index), isolate);
  }
}

// static
std::optional<Tagged<Object>> JSObject::DictionaryPropertyAt(
    DirectHandle<JSObject> object, InternalIndex dict_index, Heap* heap) {
  Tagged<Object> backing_store = object->raw_properties_or_hash(kRelaxedLoad);
  if (!IsHeapObject(backing_store)) return {};
  if (heap->IsPendingAllocation(Cast<HeapObject>(backing_store))) return {};

  if (!IsPropertyDictionary(backing_store)) return {};
  std::optional<Tagged<Object>> maybe_obj =
      Cast<PropertyDictionary>(backing_store)->TryValueAt(dict_index);

  if (!maybe_obj) return {};
  return maybe_obj.value();
}

// TODO(cbruni/jkummerow): Consider moving this into elements.cc.
bool JSObject::HasEnumerableElements() {
  // TODO(cbruni): cleanup
  Tagged<JSObject> object = *this;
  switch (object->GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS: {
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : object->elements()->length();
      return length > 0;
    }
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : elements->length();
      Isolate* isolate = GetIsolate();
      for (int i = 0; i < length; i++) {
        if (!elements->is_the_hole(isolate, i)) return true;
      }
      return false;
    }
    case HOLEY_DOUBLE_ELEMENTS: {
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : object->elements()->length();
      // Zero-length arrays would use the empty FixedArray...
      if (length == 0) return false;
      // ...so only cast to FixedDoubleArray otherwise.
      Tagged<FixedDoubleArray> elements =
          Cast<FixedDoubleArray>(object->elements());
      for (int i = 0; i < length; i++) {
        if (!elements->is_the_hole(i)) return true;
      }
      return false;
    }
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE) {
        size_t length = Cast<JSTypedArray>(object)->length();
        return length > 0;
      }

      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      {
        size_t length = Cast<JSTypedArray>(object)->GetLength();
        return length > 0;
      }
    case DICTIONARY_ELEMENTS: {
      Tagged<NumberDictionary> elements =
          Cast<NumberDictionary>(object->elements());
      return elements->NumberOfEnumerableProperties() > 0;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      // We're approximating non-empty arguments objects here.
      return true;
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
      if (Cast<String>(Cast<JSPrimitiveWrapper>(object)->value())->length() >
          0) {
        return true;
      }
      return object->elements()->length() > 0;
    case WASM_ARRAY_ELEMENTS:
      UNIMPLEMENTED();

    case NO_ELEMENTS:
      return false;
  }
  UNREACHABLE();
}

MaybeHandle<Object> JSObject::DefineOwnAccessorIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, DirectHandle<Object> getter,
    DirectHandle<Object> setter, PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  return DefineOwnAccessorIgnoreAttributes(&it, getter, setter, attributes);
}

MaybeHandle<Object> JSObject::DefineOwnAccessorIgnoreAttributes(
    LookupIterator* it, DirectHandle<Object> getter,
    DirectHandle<Object> setter, PropertyAttributes attributes) {
  Isolate* isolate = it->isolate();

  it->UpdateProtector();

  while (it->state() == LookupIterator::ACCESS_CHECK) {
    if (!it->HasAccess()) {
      RETURN_ON_EXCEPTION(
          isolate, isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()));
      UNREACHABLE();
    }
    it->Next();
  }

  auto object = Cast<JSObject>(it->GetReceiver());
  // Ignore accessors on typed arrays.
  if (it->IsElement() && object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    return it->factory()->undefined_value();
  }

  DCHECK(IsCallable(*getter) || IsUndefined(*getter, isolate) ||
         IsNull(*getter, isolate) || IsFunctionTemplateInfo(*getter));
  DCHECK(IsCallable(*setter) || IsUndefined(*setter, isolate) ||
         IsNull(*setter, isolate) || IsFunctionTemplateInfo(*setter));
  it->TransitionToAccessorProperty(getter, setter, attributes);

  return isolate->factory()->undefined_value();
}

MaybeHandle<Object> JSObject::SetAccessor(Handle<JSObject> object,
                                          Handle<Name> name,
                                          Handle<AccessorInfo> info,
                                          PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);

  // Duplicate ACCESS_CHECK outside of GetPropertyAttributes for the case that
  // the FailedAccessCheckCallbackFunction doesn't throw an exception.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    if (!it.HasAccess()) {
      RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(object));
      UNREACHABLE();
    }
    it.Next();
  }

  // Ignore accessors on typed arrays.
  if (it.IsElement() && object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    return it.factory()->undefined_value();
  }

  Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
      isolate, &it, info, Nothing<ShouldThrow>());
  MAYBE_RETURN_NULL(can_define);
  if (!can_define.FromJust()) return it.factory()->undefined_value();

  it.TransitionToAccessorPair(info, attributes);

  return object;
}

// static
Maybe<bool> JSObject::CheckIfCanDefineAsConfigurable(
    Isolate* isolate, LookupIterator* it, DirectHandle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  DCHECK(IsJSObject(*it->GetReceiver()));
  if (it->IsFound()) {
    Maybe<PropertyAttributes> attributes = GetPropertyAttributes(it);
    MAYBE_RETURN(attributes, Nothing<bool>());
    if (attributes.FromJust() != ABSENT) {
      if ((attributes.FromJust() & DONT_DELETE) != 0) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed, it->GetName()));
      }
      return Just(true);
    }
    // Property does not exist, check object extensibility.
  }
  if (!JSObject::IsExtensible(isolate, Cast<JSObject>(it->GetReceiver()))) {
    RETURN_FAILURE(
        isolate, GetShouldThrow(isolate, should_throw),
        NewTypeError(MessageTemplate::kDefineDisallowed, it->GetName()));
  }
  return Just(true);
}

Tagged<Object> JSObject::SlowReverseLookup(Tagged<Object> value) {
  if (HasFastProperties()) {
    Tagged<DescriptorArray> descs = map()->instance_descriptors();
    bool value_is_number = IsNumber(value);
    for (InternalIndex i : map()->IterateOwnDescriptors()) {
      PropertyDetails details = descs->GetDetails(i);
      if (details.location() == PropertyLocation::kField) {
        DCHECK_EQ(PropertyKind::kData, details.kind());
        FieldIndex field_index = FieldIndex::ForDetails(map(), details);
        Tagged<Object> property = RawFastPropertyAt(field_index);
        if (field_index.is_double()) {
          DCHECK(IsHeapNumber(property));
          if (value_is_number && Cast<HeapNumber>(property)->value() ==
                                     Object::NumberValue(Cast<Number>(value))) {
            return descs->GetKey(i);
          }
        } else if (property == value) {
          return descs->GetKey(i);
        }
      } else {
        DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
        if (details.kind() == PropertyKind::kData) {
          if (descs->GetStrongValue(i) == value) {
            return descs->GetKey(i);
          }
        }
      }
    }
    return GetReadOnlyRoots().undefined_value();
  } else if (IsJSGlobalObject(*this)) {
    return Cast<JSGlobalObject>(*this)
        ->global_dictionary(kAcquireLoad)
        ->SlowReverseLookup(value);
  } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return property_dictionary_swiss()->SlowReverseLookup(GetIsolate(), value);
  } else {
    return property_dictionary()->SlowReverseLookup(value);
  }
}

void JSObject::PrototypeRegistryCompactionCallback(Tagged<HeapObject> value,
                                                   int old_index,
                                                   int new_index) {
  DCHECK(IsMap(value) && Cast<Map>(value)->is_prototype_map());
  Tagged<Map> map = Cast<Map>(value);
  DCHECK(IsPrototypeInfo(map->prototype_info()));
  Tagged<PrototypeInfo> proto_info = Cast<PrototypeInfo>(map->prototype_info());
  DCHECK_EQ(old_index, proto_info->registry_slot());
  proto_info->set_registry_slot(new_index);
}

// static
void JSObject::MakePrototypesFast(Handle<Object> receiver,
                                  WhereToStart where_to_start,
                                  Isolate* isolate) {
  if (!IsJSReceiver(*receiver)) return;
  for (PrototypeIterator iter(isolate, Cast<JSReceiver>(receiver),
                              where_to_start);
       !iter.IsAtEnd(); iter.Advance()) {
    Handle<Object> current = PrototypeIterator::GetCurrent(iter);
    if (!IsJSObjectThatCanBeTrackedAsPrototype(*current)) return;
    DirectHandle<JSObject> current_obj = Cast<JSObject>(current);
    Tagged<Map> current_map = current_obj->map();
    if (current_map->is_prototype_map()) {
      // If the map is already marked as should be fast, we're done. Its
      // prototypes will have been marked already as well.
      if (current_map->should_be_fast_prototype_map()) return;
      DirectHandle<Map> map(current_map, isolate);
      Map::SetShouldBeFastPrototypeMap(map, true, isolate);
      JSObject::OptimizeAsPrototype(current_obj);
    }
  }
}

static bool PrototypeBenefitsFromNormalization(Tagged<JSObject> object) {
  DisallowGarbageCollection no_gc;
  if (!object->HasFastProperties()) return false;
  if (IsJSGlobalProxy(object)) return false;
  // TODO(v8:11248) make bootstrapper create dict mode prototypes, too?
  if (object->GetIsolate()->bootstrapper()->IsActive()) return false;
  if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) return true;
  return !object->map()->is_prototype_map() ||
         !object->map()->should_be_fast_prototype_map();
}

// static
void JSObject::OptimizeAsPrototype(DirectHandle<JSObject> object,
                                   bool enable_setup_mode) {
  DCHECK(IsJSObjectThatCanBeTrackedAsPrototype(*object));
  if (IsJSGlobalObject(*object)) return;
  Isolate* isolate = object->GetIsolate();
  if (object->map()->is_prototype_map()) {
    if (enable_setup_mode && PrototypeBenefitsFromNormalization(*object)) {
      // This is the only way PrototypeBenefitsFromNormalization can be true:
      DCHECK(!object->map()->should_be_fast_prototype_map());
      // First normalize to ensure all JSFunctions are DATA_CONSTANT.
      constexpr bool kUseCache = true;
      JSObject::NormalizeProperties(isolate, object, KEEP_INOBJECT_PROPERTIES,
                                    0, kUseCache, "NormalizeAsPrototype");
    }
    if (!V8_DICT_PROPERTY_CONST_TRACKING_BOOL &&
        object->map()->should_be_fast_prototype_map() &&
        !object->HasFastProperties()) {
      JSObject::MigrateSlowToFast(object, 0, "OptimizeAsPrototype");
    }
  } else {
    DirectHandle<Map> new_map;
    if (enable_setup_mode && PrototypeBenefitsFromNormalization(*object)) {
#if DEBUG
      DirectHandle<Map> old_map(object->map(isolate), isolate);
#endif  // DEBUG
      // First normalize to ensure all JSFunctions are DATA_CONSTANT. Don't use
      // the cache, since we're going to use the normalized version directly,
      // without making a copy.
      constexpr bool kUseCache = false;
      JSObject::NormalizeProperties(isolate, object, KEEP_INOBJECT_PROPERTIES,
                                    0, kUseCache,
                                    "NormalizeAndCopyAsPrototype");
      // A new map was created.
      DCHECK_NE(*old_map, object->map(isolate));

      new_map = direct_handle(object->map(isolate), isolate);
    } else {
      new_map =
          Map::Copy(isolate, handle(object->map(), isolate), "CopyAsPrototype");
    }
    new_map->set_is_prototype_map(true);

    // Replace the pointer to the exact constructor with the Object function
    // from the same context if undetectable from JS. This is to avoid keeping
    // memory alive unnecessarily.
    Tagged<Object> maybe_constructor = new_map->GetConstructorRaw();
    Tagged<Tuple2> tuple;
    if (IsTuple2(maybe_constructor)) {
      // Handle the {constructor, non-instance_prototype} tuple case if the map
      // has non-instance prototype.
      tuple = Cast<Tuple2>(maybe_constructor);
      maybe_constructor = tuple->value1();
    }
    if (IsJSFunction(maybe_constructor)) {
      Tagged<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
      if (!constructor->shared()->IsApiFunction()) {
        Tagged<NativeContext> context = constructor->native_context();
        Tagged<JSFunction> object_function = context->object_function();
        if (!tuple.is_null()) {
          tuple->set_value1(object_function);
       
"""


```