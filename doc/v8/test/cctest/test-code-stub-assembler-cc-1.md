Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is part 2 of 6. The code seems to be testing different lookup functionalities related to JavaScript objects and their properties in the V8 engine.

Here's a breakdown of the code's functionality:

1. **Dictionary Lookups (NameDictionary, GlobalDictionary, NumberDictionary):** It tests the `NameDictionaryLookup` and `NumberDictionaryLookup` functions, which are used to find entries (properties) in different types of dictionaries used by V8.

2. **Transition Lookup:** It tests the `TransitionLookup` function, which is used to find transitions in the `TransitionArray` of a `Map` object. These transitions represent changes in the structure of objects.

3. **`TryHasOwnProperty`:** It tests the `TryHasOwnProperty` function, which checks if an object has a direct own property with a given name. It tests this for various object types (fast objects, dictionary objects, global objects, proxies).

4. **`TryGetOwnProperty`:** It tests the `TryGetOwnProperty` function, which attempts to retrieve the value of an own property. It also covers different object types and property types (data properties, accessors).

5. **`TryLookupElement`:** It tests the `TryLookupElement` function, which attempts to find an element at a specific index in an object (primarily arrays and array-like objects). It tests different element kinds (packed, holey, typed arrays, string wrappers).

Based on this analysis, I can summarize the functionality of this part of the test file.
这段代码主要测试了V8中关于**属性查找**和**元素查找**的几种不同场景，并使用了`CodeStubAssembler`来生成测试代码。以下是其功能的归纳：

**总体功能：测试 V8 中不同类型的属性和元素查找操作的正确性。**

**具体功能点：**

1. **字典查找 (Dictionary Lookup):**
   - 测试了 `NameDictionaryLookup` 和 `GlobalDictionaryLookup`，它们分别用于在 `NameDictionary` 和 `GlobalDictionary` 中查找属性。
   - 测试了 `NumberDictionaryLookup`，用于在 `NumberDictionary` 中查找数字索引的属性。

2. **转换查找 (Transition Lookup):**
   - 测试了 `TransitionLookup`，用于在对象的 `TransitionArray` 中查找特定的属性转换。`TransitionArray` 记录了对象形状的变化。

3. **`TryHasOwnProperty`:**
   - 测试了 `TryHasOwnProperty` 指令，用于检查对象自身是否拥有指定名称的属性，不包括原型链上的属性。
   - 涵盖了不同类型的对象：快速对象（有和无内联属性）、字典模式对象、全局对象和代理对象。

4. **`TryGetOwnProperty`:**
   - 测试了 `TryGetOwnProperty` 指令，用于尝试获取对象自身指定名称的属性值。
   - 涵盖了不同类型的对象，以及不同类型的属性：数据属性和访问器属性 (getter/setter)。

5. **`TryLookupElement`:**
   - 测试了 `TryLookupElement` 指令，用于尝试查找对象中指定索引的元素。
   - 涵盖了不同类型的数组和类数组对象：
     - 密集数组 (Packed Smi Elements, Packed Elements)
     - 稀疏数组 (Holey Smi Elements, Holey Elements)
     - 类型化数组 (Typed Array)
     - 字符串包装对象 (String Wrapper)

**可以理解为，这段代码是 V8 引擎中用于测试低级别代码生成器 (`CodeStubAssembler`) 是否能正确实现各种属性和元素查找逻辑的单元测试。**

**如果 v8/test/cctest/test-code-stub-assembler.cc 以 .tq 结尾，那它是个 v8 torque 源代码:**

本文件以 `.cc` 结尾，说明它是 C++ 源代码，而不是 Torque 源代码。Torque 是一种用于定义 V8 内置函数的领域特定语言，文件通常以 `.tq` 结尾。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

是的，这些测试的功能都与 JavaScript 中访问对象属性和元素的功能息息相关。

* **字典查找:** 对应 JavaScript 中访问对象的属性，例如 `object.propertyName` 或 `object['propertyName']`。当对象属性数量很多或者属性名不是简单的字符串时，V8 可能会使用字典来存储属性。
* **转换查找:** 当你为一个对象动态添加属性时，对象的“形状”会发生变化，V8 会记录这些变化，用于优化后续的属性访问。
* **`TryHasOwnProperty`:** 对应 JavaScript 中的 `object.hasOwnProperty('propertyName')` 方法。
* **`TryGetOwnProperty`:** 对应 JavaScript 中尝试直接获取对象自身属性的值，例如 `Object.getOwnPropertyDescriptor(object, 'propertyName')` 并访问其 `value` 属性。
* **`TryLookupElement`:** 对应 JavaScript 中访问数组或类数组对象的元素，例如 `array[index]`。

**JavaScript 示例：**

```javascript
const obj = { a: 1, b: 2 };
const arr = [10, 20, 30];

// 字典查找 (可能在底层)
console.log(obj.a);
console.log(obj['b']);

// hasOwnProperty
console.log(obj.hasOwnProperty('a')); // 输出 true
console.log(obj.hasOwnProperty('toString')); // 输出 false

// 获取自身属性
console.log(Object.getOwnPropertyDescriptor(obj, 'a').value);

// 元素查找
console.log(arr[0]);
```

**如果有代码逻辑推理，请给出假设输入与输出：**

**以 `TryHasOwnProperty` 测试中的一个场景为例：**

**假设输入：**

* `object`: 一个 JavaScript 对象 `{ a: 1, bb: 2 }`
* `unique_name`: 字符串 `"bb"`

**代码逻辑推理：**

`TryHasOwnProperty` 函数会检查 `object` 自身是否有名为 `"bb"` 的属性。因为对象 `obj` 确实拥有名为 `"bb"` 的属性，所以 `TryHasOwnProperty` 应该返回 `kFound`。

**预期输出：**

`ft.CheckTrue(object, name, expect_found)` 会断言结果为 `true`，因为 `TryHasOwnProperty` 应该返回表示找到的结果。

**如果涉及用户常见的编程错误，请举例说明：**

* **使用 `hasOwnProperty` 和原型链：** 用户可能会错误地认为 `hasOwnProperty` 会检查原型链上的属性。例如：

   ```javascript
   function MyClass() {}
   MyClass.prototype.sharedProp = 10;
   const instance = new MyClass();
   console.log(instance.hasOwnProperty('sharedProp')); // 输出 false
   console.log(instance.sharedProp); // 输出 10
   ```
   `TryHasOwnProperty` 的测试就覆盖了这种场景，确保 V8 的实现符合 JavaScript 的规范。

* **访问不存在的属性/元素：** 用户可能会尝试访问对象中不存在的属性或数组中超出索引范围的元素。例如：

   ```javascript
   const obj = { a: 1 };
   console.log(obj.b); // 输出 undefined

   const arr = [1, 2];
   console.log(arr[2]); // 输出 undefined
   ```
   `TryGetOwnProperty` 和 `TryLookupElement` 的测试会验证 V8 如何处理这些情况。

**这是第2部分，共6部分，请归纳一下它的功能:**

**第 2 部分主要集中在测试 V8 引擎中用于查找对象属性和元素的底层机制的正确性，包括字典查找、转换查找以及直接的属性和元素查找操作。它通过 `CodeStubAssembler` 生成测试代码，并针对不同的对象类型和属性/元素类型进行验证。**

Prompt: 
```
这是目录为v8/test/cctest/test-code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
ys); i++) {
    InternalIndex entry = dictionary->FindEntry(isolate, non_existing_keys[i]);
    CHECK(entry.is_not_found());

    ft.CheckTrue(dictionary, non_existing_keys[i], expect_not_found);
  }
}

}  // namespace

TEST(NameDictionaryLookup) { TestNameDictionaryLookup<NameDictionary>(); }

TEST(GlobalDictionaryLookup) { TestNameDictionaryLookup<GlobalDictionary>(); }

TEST(NumberDictionaryLookup) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 4;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kNotFound };
  {
    auto dictionary = m.Parameter<NumberDictionary>(1);
    TNode<IntPtrT> key = m.SmiUntag(m.Parameter<Smi>(2));
    auto expected_result = m.Parameter<Smi>(3);
    auto expected_arg = m.Parameter<Object>(4);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m);
    TVariable<IntPtrT> var_entry(&m);

    m.NumberDictionaryLookup(dictionary, key, &if_found, &var_entry,
                             &if_not_found);
    m.BIND(&if_found);
    m.GotoIfNot(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &failed);
    m.Branch(m.WordEqual(m.SmiUntag(m.CAST(expected_arg)), var_entry.value()),
             &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);

  const int kKeysCount = 1000;
  Handle<NumberDictionary> dictionary =
      NumberDictionary::New(isolate, kKeysCount);
  uint32_t keys[kKeysCount];

  DirectHandle<Object> fake_value(Smi::FromInt(42), isolate);
  PropertyDetails fake_details = PropertyDetails::Empty();

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  for (int i = 0; i < kKeysCount; i++) {
    int random_key = rand_gen.NextInt(Smi::kMaxValue);
    keys[i] = static_cast<uint32_t>(random_key);
    if (dictionary->FindEntry(isolate, keys[i]).is_found()) continue;

    dictionary = NumberDictionary::Add(isolate, dictionary, keys[i], fake_value,
                                       fake_details);
  }

  // Now try querying existing keys.
  for (int i = 0; i < kKeysCount; i++) {
    InternalIndex entry = dictionary->FindEntry(isolate, keys[i]);
    CHECK(entry.is_found());

    Handle<Object> key(Smi::FromInt(keys[i]), isolate);
    Handle<Object> expected_entry(Smi::FromInt(entry.as_int()), isolate);
    ft.CheckTrue(dictionary, key, expect_found, expected_entry);
  }

  // Now try querying random keys which do not exist in the dictionary.
  for (int i = 0; i < kKeysCount;) {
    int random_key = rand_gen.NextInt(Smi::kMaxValue);
    InternalIndex entry = dictionary->FindEntry(isolate, random_key);
    if (entry.is_found()) continue;
    i++;

    Handle<Object> key(Smi::FromInt(random_key), isolate);
    ft.CheckTrue(dictionary, key, expect_not_found);
  }
}

TEST(TransitionLookup) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 4;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));

  enum Result { kFound, kNotFound };

  class TempAssembler : public CodeStubAssembler {
   public:
    explicit TempAssembler(compiler::CodeAssemblerState* state)
        : CodeStubAssembler(state) {}

    void Generate() {
      auto transitions = Parameter<TransitionArray>(1);
      auto name = Parameter<Name>(2);
      auto expected_result = Parameter<Smi>(3);
      auto expected_arg = Parameter<Object>(4);

      Label passed(this), failed(this);
      Label if_found(this), if_not_found(this);
      TVARIABLE(IntPtrT, var_transition_index);

      TransitionLookup(name, transitions, &if_found, &var_transition_index,
                       &if_not_found);

      BIND(&if_found);
      GotoIfNot(TaggedEqual(expected_result, SmiConstant(kFound)), &failed);
      Branch(TaggedEqual(expected_arg, SmiTag(var_transition_index.value())),
             &passed, &failed);

      BIND(&if_not_found);
      Branch(TaggedEqual(expected_result, SmiConstant(kNotFound)), &passed,
             &failed);

      BIND(&passed);
      Return(BooleanConstant(true));

      BIND(&failed);
      Return(BooleanConstant(false));
    }
  };
  TempAssembler(asm_tester.state()).Generate();

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);

  const int ATTRS_COUNT = (READ_ONLY | DONT_ENUM | DONT_DELETE) + 1;
  static_assert(ATTRS_COUNT == 8);

  const int kKeysCount = 300;
  Handle<Map> root_map = Map::Create(isolate, 0);
  Handle<Name> keys[kKeysCount];

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  Factory* factory = isolate->factory();
  Handle<FieldType> any = FieldType::Any(isolate);

  for (int i = 0; i < kKeysCount; i++) {
    Handle<Name> name;
    if (i % 30 == 0) {
      name = factory->NewPrivateSymbol();
    } else if (i % 10 == 0) {
      name = factory->NewSymbol();
    } else {
      int random_key = rand_gen.NextInt(Smi::kMaxValue);
      name = CcTest::MakeName("p", random_key);
    }
    keys[i] = name;

    bool is_private = name->IsPrivate();
    PropertyAttributes base_attributes = is_private ? DONT_ENUM : NONE;

    // Ensure that all the combinations of cases are covered:
    // 1) there is a "base" attributes transition
    // 2) there are other non-base attributes transitions
    if ((i & 1) == 0) {
      CHECK(!Map::CopyWithField(isolate, root_map, name, any, base_attributes,
                                PropertyConstness::kMutable,
                                Representation::Tagged(), INSERT_TRANSITION)
                 .is_null());
    }

    if ((i & 2) == 0) {
      for (int j = 0; j < ATTRS_COUNT; j++) {
        auto attributes = PropertyAttributesFromInt(j);
        if (attributes == base_attributes) continue;
        // Don't add private symbols with enumerable attributes.
        if (is_private && ((attributes & DONT_ENUM) == 0)) continue;
        CHECK(!Map::CopyWithField(isolate, root_map, name, any, attributes,
                                  PropertyConstness::kMutable,
                                  Representation::Tagged(), INSERT_TRANSITION)
                   .is_null());
      }
    }
  }

  CHECK(IsTransitionArray(
      root_map->raw_transitions().GetHeapObjectAssumeStrong()));
  Handle<TransitionArray> transitions(
      Cast<TransitionArray>(
          root_map->raw_transitions().GetHeapObjectAssumeStrong()),
      isolate);
  DCHECK(transitions->IsSortedNoDuplicates());

  // Ensure we didn't overflow transition array and therefore all the
  // combinations of cases are covered.
  CHECK(TransitionsAccessor::CanHaveMoreTransitions(isolate, root_map));

  // Now try querying keys.
  bool positive_lookup_tested = false;
  bool negative_lookup_tested = false;
  for (int i = 0; i < kKeysCount; i++) {
    Handle<Name> name = keys[i];

    int transition_number = transitions->SearchNameForTesting(*name);

    if (transition_number != TransitionArray::kNotFound) {
      Handle<Smi> expected_value(
          Smi::FromInt(TransitionArray::ToKeyIndex(transition_number)),
          isolate);
      ft.CheckTrue(transitions, name, expect_found, expected_value);
      positive_lookup_tested = true;
    } else {
      ft.CheckTrue(transitions, name, expect_not_found);
      negative_lookup_tested = true;
    }
  }
  CHECK(positive_lookup_tested);
  CHECK(negative_lookup_tested);
}

namespace {

void AddProperties(Handle<JSObject> object, Handle<Name> names[],
                   size_t count) {
  Isolate* isolate = object->GetIsolate();
  for (size_t i = 0; i < count; i++) {
    DirectHandle<Object> value(Smi::FromInt(static_cast<int>(42 + i)), isolate);
    JSObject::AddProperty(isolate, object, names[i], value, NONE);
  }
}

Handle<AccessorPair> CreateAccessorPair(FunctionTester* ft,
                                        const char* getter_body,
                                        const char* setter_body) {
  Handle<AccessorPair> pair = ft->isolate->factory()->NewAccessorPair();
  if (getter_body) {
    pair->set_getter(*ft->NewFunction(getter_body));
  }
  if (setter_body) {
    pair->set_setter(*ft->NewFunction(setter_body));
  }
  return pair;
}

void AddProperties(Handle<JSObject> object, Handle<Name> names[],
                   size_t names_count, Handle<Object> values[],
                   size_t values_count, int seed = 0) {
  Isolate* isolate = object->GetIsolate();
  for (size_t i = 0; i < names_count; i++) {
    Handle<Object> value = values[(seed + i) % values_count];
    if (IsAccessorPair(*value)) {
      DirectHandle<AccessorPair> pair = Cast<AccessorPair>(value);
      DirectHandle<Object> getter(pair->getter(), isolate);
      DirectHandle<Object> setter(pair->setter(), isolate);
      JSObject::DefineOwnAccessorIgnoreAttributes(object, names[i], getter,
                                                  setter, NONE)
          .Check();
    } else {
      JSObject::AddProperty(isolate, object, names[i], value, NONE);
    }
  }
}

}  // namespace

TEST(TryHasOwnProperty) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kNotFound, kBailout };
  {
    auto object = m.Parameter<HeapObject>(1);
    auto unique_name = m.Parameter<Name>(2);
    TNode<MaybeObject> expected_result = m.UncheckedParameter<MaybeObject>(3);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m), if_bailout(&m);

    TNode<Map> map = m.LoadMap(object);
    TNode<Uint16T> instance_type = m.LoadMapInstanceType(map);

    m.TryHasOwnProperty(object, map, instance_type, unique_name, &if_found,
                        &if_not_found, &if_bailout);

    m.BIND(&if_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&if_bailout);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kBailout))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);
  Handle<Object> expect_bailout(Smi::FromInt(kBailout), isolate);

  Factory* factory = isolate->factory();

  Handle<Name> deleted_property_name =
      factory->InternalizeUtf8String("deleted");

  Handle<Name> names[] = {
      factory->InternalizeUtf8String("a"),
      factory->InternalizeUtf8String("bb"),
      factory->InternalizeUtf8String("ccc"),
      factory->InternalizeUtf8String("dddd"),
      factory->InternalizeUtf8String("eeeee"),
      factory->InternalizeUtf8String(""),
      factory->InternalizeUtf8String("name"),
      factory->NewSymbol(),
      factory->NewPrivateSymbol(),
  };

  std::vector<Handle<JSObject>> objects;

  {
    // Fast object, no inobject properties.
    int inobject_properties = 0;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names));
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, all inobject properties.
    int inobject_properties = arraysize(names) * 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names));
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, half inobject properties.
    int inobject_properties = arraysize(names) / 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names));
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Dictionary mode object.
    Handle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSObject> object = factory->NewJSObject(function);
    AddProperties(object, names, arraysize(names));
    JSObject::NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                                  "test");

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Global object.
    Handle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    JSFunction::EnsureHasInitialMap(function);
    function->initial_map()->set_instance_type(JS_GLOBAL_OBJECT_TYPE);
    function->initial_map()->set_instance_size(JSGlobalObject::kHeaderSize);
    function->initial_map()->SetInObjectUnusedPropertyFields(0);
    function->initial_map()->SetInObjectPropertiesStartInWords(
        function->initial_map()->instance_size_in_words());
    function->initial_map()->set_is_prototype_map(true);
    function->initial_map()->set_is_dictionary_map(true);
    function->initial_map()->set_may_have_interesting_properties(true);
    Handle<JSObject> object = factory->NewJSGlobalObject(function);
    AddProperties(object, names, arraysize(names));

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_GLOBAL_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    for (Handle<JSObject> object : objects) {
      for (size_t name_index = 0; name_index < arraysize(names); name_index++) {
        Handle<Name> name = names[name_index];
        CHECK(JSReceiver::HasProperty(isolate, object, name).FromJust());
        ft.CheckTrue(object, name, expect_found);
      }
    }
  }

  {
    Handle<Name> non_existing_names[] = {
        factory->NewSymbol(),
        factory->InternalizeUtf8String("ne_a"),
        factory->InternalizeUtf8String("ne_bb"),
        factory->NewPrivateSymbol(),
        factory->InternalizeUtf8String("ne_ccc"),
        factory->InternalizeUtf8String("ne_dddd"),
        deleted_property_name,
    };
    for (Handle<JSObject> object : objects) {
      for (size_t key_index = 0; key_index < arraysize(non_existing_names);
           key_index++) {
        Handle<Name> name = non_existing_names[key_index];
        CHECK(!JSReceiver::HasProperty(isolate, object, name).FromJust());
        ft.CheckTrue(object, name, expect_not_found);
      }
    }
  }

  {
    DirectHandle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSProxy> object = factory->NewJSProxy(function, objects[0]);
    CHECK_EQ(JS_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, names[0], expect_bailout);
  }

  {
    Handle<JSObject> object = isolate->global_proxy();
    CHECK_EQ(JS_GLOBAL_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, names[0], expect_bailout);
  }
}

TEST(TryGetOwnProperty) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();

  const int kNumParams = 2;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  Handle<Symbol> not_found_symbol = factory->NewSymbol();
  Handle<Symbol> bailout_symbol = factory->NewSymbol();
  {
    auto object = m.Parameter<JSReceiver>(1);
    auto unique_name = m.Parameter<Name>(2);
    auto context = m.GetJSContextParameter();

    TVariable<Object> var_value(&m);
    Label if_found(&m), if_not_found(&m), if_bailout(&m);

    TNode<Map> map = m.LoadMap(object);
    TNode<Uint16T> instance_type = m.LoadMapInstanceType(map);

    m.TryGetOwnProperty(context, object, object, map, instance_type,
                        unique_name, &if_found, &var_value, &if_not_found,
                        &if_bailout);

    m.BIND(&if_found);
    m.Return(m.UncheckedCast<Object>(var_value.value()));

    m.BIND(&if_not_found);
    m.Return(m.HeapConstantNoHole(not_found_symbol));

    m.BIND(&if_bailout);
    m.Return(m.HeapConstantNoHole(bailout_symbol));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Handle<Name> deleted_property_name =
      factory->InternalizeUtf8String("deleted");

  Handle<Name> names[] = {
      factory->InternalizeUtf8String("bb"),
      factory->NewSymbol(),
      factory->InternalizeUtf8String("a"),
      factory->InternalizeUtf8String("ccc"),
      factory->InternalizeUtf8String("esajefe"),
      factory->NewPrivateSymbol(),
      factory->InternalizeUtf8String("eeeee"),
      factory->InternalizeUtf8String("p1"),
      factory->InternalizeUtf8String("acshw23e"),
      factory->InternalizeUtf8String(""),
      factory->InternalizeUtf8String("dddd"),
      factory->NewPrivateSymbol(),
      factory->InternalizeUtf8String("name"),
      factory->InternalizeUtf8String("p2"),
      factory->InternalizeUtf8String("p3"),
      factory->InternalizeUtf8String("p4"),
      factory->NewPrivateSymbol(),
  };
  Handle<Object> values[] = {
      factory->NewFunctionForTesting(factory->empty_string()),
      factory->NewSymbol(),
      factory->InternalizeUtf8String("a"),
      CreateAccessorPair(&ft, "() => 188;", "() => 199;"),
      factory->NewFunctionForTesting(factory->InternalizeUtf8String("bb")),
      factory->InternalizeUtf8String("ccc"),
      CreateAccessorPair(&ft, "() => 88;", nullptr),
      handle(Smi::FromInt(1), isolate),
      factory->InternalizeUtf8String(""),
      CreateAccessorPair(&ft, nullptr, "() => 99;"),
      factory->NewHeapNumber(4.2),
      handle(Smi::FromInt(153), isolate),
      factory->NewJSObject(
          factory->NewFunctionForTesting(factory->empty_string())),
      factory->NewPrivateSymbol(),
  };
  static_assert(arraysize(values) < arraysize(names));

  base::RandomNumberGenerator rand_gen(v8_flags.random_seed);

  std::vector<Handle<JSObject>> objects;

  {
    // Fast object, no inobject properties.
    int inobject_properties = 0;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, all inobject properties.
    int inobject_properties = arraysize(names) * 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Fast object, half inobject properties.
    int inobject_properties = arraysize(names) / 2;
    DirectHandle<Map> map = Map::Create(isolate, inobject_properties);
    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK_EQ(inobject_properties, object->map()->GetInObjectProperties());
    CHECK(!object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Dictionary mode object.
    Handle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSObject> object = factory->NewJSObject(function);
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());
    JSObject::NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                                  "test");

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  {
    // Global object.
    Handle<JSGlobalObject> object = isolate->global_object();
    AddProperties(object, names, arraysize(names), values, arraysize(values),
                  rand_gen.NextInt());

    JSObject::AddProperty(isolate, object, deleted_property_name, object, NONE);
    CHECK(JSObject::DeleteProperty(isolate, object, deleted_property_name,
                                   LanguageMode::kSloppy)
              .FromJust());

    CHECK_EQ(JS_GLOBAL_OBJECT_TYPE, object->map()->instance_type());
    CHECK(object->map()->is_dictionary_map());
    objects.push_back(object);
  }

  // TODO(ishell): test proxy and interceptors when they are supported.

  {
    for (Handle<JSObject> object : objects) {
      for (size_t name_index = 0; name_index < arraysize(names); name_index++) {
        Handle<Name> name = names[name_index];
        DirectHandle<Object> expected_value =
            JSReceiver::GetProperty(isolate, object, name).ToHandleChecked();
        DirectHandle<Object> value = ft.Call(object, name).ToHandleChecked();
        CHECK(Object::SameValue(*expected_value, *value));
      }
    }
  }

  {
    Handle<Name> non_existing_names[] = {
        factory->NewSymbol(),
        factory->InternalizeUtf8String("ne_a"),
        factory->InternalizeUtf8String("ne_bb"),
        factory->NewPrivateSymbol(),
        factory->InternalizeUtf8String("ne_ccc"),
        factory->InternalizeUtf8String("ne_dddd"),
        deleted_property_name,
    };
    for (Handle<JSObject> object : objects) {
      for (size_t key_index = 0; key_index < arraysize(non_existing_names);
           key_index++) {
        Handle<Name> name = non_existing_names[key_index];
        DirectHandle<Object> expected_value =
            JSReceiver::GetProperty(isolate, object, name).ToHandleChecked();
        CHECK(IsUndefined(*expected_value, isolate));
        DirectHandle<Object> value = ft.Call(object, name).ToHandleChecked();
        CHECK_EQ(*not_found_symbol, *value);
      }
    }
  }

  {
    DirectHandle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSProxy> object = factory->NewJSProxy(function, objects[0]);
    CHECK_EQ(JS_PROXY_TYPE, object->map()->instance_type());
    DirectHandle<Object> value = ft.Call(object, names[0]).ToHandleChecked();
    // Proxies are not supported yet.
    CHECK_EQ(*bailout_symbol, *value);
  }

  {
    Handle<JSObject> object = isolate->global_proxy();
    CHECK_EQ(JS_GLOBAL_PROXY_TYPE, object->map()->instance_type());
    // Global proxies are not supported yet.
    DirectHandle<Object> value = ft.Call(object, names[0]).ToHandleChecked();
    CHECK_EQ(*bailout_symbol, *value);
  }
}

namespace {

void AddElement(Handle<JSObject> object, uint32_t index,
                DirectHandle<Object> value,
                PropertyAttributes attributes = NONE) {
  JSObject::AddDataElement(object, index, value, attributes);
}

}  // namespace

TEST(TryLookupElement) {
  Isolate* isolate(CcTest::InitIsolateOnce());

  const int kNumParams = 3;
  CodeAssemblerTester asm_tester(isolate, JSParameterCount(kNumParams));
  CodeStubAssembler m(asm_tester.state());

  enum Result { kFound, kAbsent, kNotFound, kBailout };
  {
    auto object = m.Parameter<HeapObject>(1);
    TNode<IntPtrT> index = m.SmiUntag(m.Parameter<Smi>(2));
    TNode<MaybeObject> expected_result = m.UncheckedParameter<MaybeObject>(3);

    Label passed(&m), failed(&m);
    Label if_found(&m), if_not_found(&m), if_bailout(&m), if_absent(&m);

    TNode<Map> map = m.LoadMap(object);
    TNode<Uint16T> instance_type = m.LoadMapInstanceType(map);

    m.TryLookupElement(object, map, instance_type, index, &if_found, &if_absent,
                       &if_not_found, &if_bailout);

    m.BIND(&if_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kFound))),
        &passed, &failed);

    m.BIND(&if_absent);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kAbsent))),
        &passed, &failed);

    m.BIND(&if_not_found);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kNotFound))),
        &passed, &failed);

    m.BIND(&if_bailout);
    m.Branch(
        m.TaggedEqual(expected_result, m.SmiConstant(Smi::FromInt(kBailout))),
        &passed, &failed);

    m.BIND(&passed);
    m.Return(m.BooleanConstant(true));

    m.BIND(&failed);
    m.Return(m.BooleanConstant(false));
  }

  FunctionTester ft(asm_tester.GenerateCode(), kNumParams);

  Factory* factory = isolate->factory();
  Handle<Object> smi0(Smi::zero(), isolate);
  Handle<Object> smi1(Smi::FromInt(1), isolate);
  Handle<Object> smi7(Smi::FromInt(7), isolate);
  Handle<Object> smi13(Smi::FromInt(13), isolate);
  Handle<Object> smi42(Smi::FromInt(42), isolate);

  Handle<Object> expect_found(Smi::FromInt(kFound), isolate);
  Handle<Object> expect_absent(Smi::FromInt(kAbsent), isolate);
  Handle<Object> expect_not_found(Smi::FromInt(kNotFound), isolate);
  Handle<Object> expect_bailout(Smi::FromInt(kBailout), isolate);

#define CHECK_FOUND(object, index)                                  \
  CHECK(JSReceiver::HasElement(isolate, object, index).FromJust()); \
  ft.CheckTrue(object, smi##index, expect_found);

#define CHECK_NOT_FOUND(object, index)                               \
  CHECK(!JSReceiver::HasElement(isolate, object, index).FromJust()); \
  ft.CheckTrue(object, smi##index, expect_not_found);

#define CHECK_ABSENT(object, index)                  \
  {                                                  \
    Handle<Smi> smi(Smi::FromInt(index), isolate);   \
    PropertyKey key(isolate, smi);                   \
    LookupIterator it(isolate, object, key);         \
    CHECK(!JSReceiver::HasProperty(&it).FromJust()); \
    ft.CheckTrue(object, smi, expect_absent);        \
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, PACKED_SMI_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 1, smi0);
    CHECK_EQ(PACKED_SMI_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_NOT_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, HOLEY_SMI_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 13, smi0);
    CHECK_EQ(HOLEY_SMI_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_NOT_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, PACKED_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 1, smi0);
    CHECK_EQ(PACKED_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_NOT_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSArray> object = factory->NewJSArray(0, HOLEY_ELEMENTS);
    AddElement(object, 0, smi0);
    AddElement(object, 13, smi0);
    CHECK_EQ(HOLEY_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_NOT_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    v8::Local<v8::ArrayBuffer> buffer =
        v8::ArrayBuffer::New(reinterpret_cast<v8::Isolate*>(isolate), 8);
    Handle<JSTypedArray> object = factory->NewJSTypedArray(
        kExternalInt32Array, v8::Utils::OpenHandle(*buffer), 0, 2);

    CHECK_EQ(INT32_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_ABSENT(object, -10);
    CHECK_ABSENT(object, 13);
    CHECK_ABSENT(object, 42);

    {
      std::shared_ptr<v8::BackingStore> backing_store =
          buffer->GetBackingStore();
      buffer->Detach(v8::Local<v8::Value>()).Check();
    }
    CHECK_ABSENT(object, 0);
    CHECK_ABSENT(object, 1);
    CHECK_ABSENT(object, -10);
    CHECK_ABSENT(object, 13);
    CHECK_ABSENT(object, 42);
  }

  {
    Handle<JSFunction> constructor = isolate->string_function();
    Handle<JSObject> object = factory->NewJSObject(constructor);
    DirectHandle<String> str = factory->InternalizeUtf8String("ab");
    Cast<JSPrimitiveWrapper>(object)->set_value(*str);
    AddElement(object, 13, smi0);
    CHECK_EQ(FAST_STRING_WRAPPER_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  {
    Handle<JSFunction> constructor = isolate->string_function();
    Handle<JSObject> object = factory->NewJSObject(constructor);
    DirectHandle<String> str = factory->InternalizeUtf8String("ab");
    Cast<JSPrimitiveWrapper>(object)->set_value(*str);
    AddElement(object, 13, smi0);
    JSObject::NormalizeElements(object);
    CHECK_EQ(SLOW_STRING_WRAPPER_ELEMENTS, object->map()->elements_kind());

    CHECK_FOUND(object, 0);
    CHECK_FOUND(object, 1);
    CHECK_NOT_FOUND(object, 7);
    CHECK_FOUND(object, 13);
    CHECK_NOT_FOUND(object, 42);
  }

  // TODO(ishell): uncomment once NO_ELEMENTS kind is supported.
  //  {
  //    Handle<Map> map = Map::Create(isolate, 0);
  //    map->set_elements_kind(NO_ELEMENTS);
  //    Handle<JSObject> object = factory->NewJSObjectFromMap(map);
  //    CHECK_EQ(NO_ELEMENTS, object->map()->elements_kind());
  //
  //    CHECK_NOT_FOUND(object, 0);
  //    CHECK_NOT_FOUND(object, 1);
  //    CHECK_NOT_FOUND(object, 7);
  //    CHECK_NOT_FOUND(object, 13);
  //    CHECK_NOT_FOUND(object, 42);
  //  }

#undef CHECK_FOUND
#undef CHECK_NOT_FOUND
#undef CHECK_ABSENT

  {
    DirectHandle<JSArray> handler = factory->NewJSArray(0);
    DirectHandle<JSFunction> function =
        factory->NewFunctionForTesting(factory->empty_string());
    Handle<JSProxy> object = factory->NewJSProxy(function, handler);
    CHECK_EQ(JS_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, smi0, expect_bailout);
  }

  {
    Handle<JSObject> object = isolate->global_object();
    CHECK_EQ(JS_GLOBAL_OBJECT_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, smi0, expect_bailout);
  }

  {
    Handle<JSObject> object = isolate->global_proxy();
    CHECK_EQ(JS_GLOBAL_PROXY_TYPE, object->map()->instance_type());
    ft.CheckTrue(object, smi0, expect_bailout);
  }
}

TEST(AllocateJSObjectFromMap) {
  Isolate* isolate(CcTest::InitIsolateOnce());
  Factory* factory = isolate->factory();

  const int kNumParams = 3;
  CodeAss
"""


```