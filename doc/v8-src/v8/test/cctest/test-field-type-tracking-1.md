Response: The user wants a summary of the C++ code provided. The code seems to be testing the V8 Javascript engine's field type tracking and how it handles changes to object properties and elements.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The filename "test-field-type-tracking.cc" and the numerous `TEST` macros clearly indicate this is a test file. The name suggests it's testing how V8 tracks the types of object fields.

2. **Look for key concepts and keywords:**  Scan the code for recurring terms. "Map", "FieldType", "Representation", "PropertyConstness", "ElementsKind", "Transition", "ReconfigureProperty", "Expectations", "GeneralizeField", "Deprecated" appear frequently. These are all related to V8's object model and how it optimizes property access.

3. **Group related tests:** Notice the comments that group tests, like "A set of tests for elements kind reconfiguration case" or "A set of tests checking split map deprecation." This provides a higher-level structure to the functionality being tested.

4. **Focus on the "what" and "why" of the tests:** For each group of tests, try to understand what specific scenario is being tested and why it's important. For instance, tests about "elements kind reconfiguration" are checking how V8 handles changes in the way array elements are stored (e.g., from SMI to doubles). Tests about "split map deprecation" are examining what happens when a map (V8's internal representation of object structure) becomes outdated.

5. **Identify the relationship to JavaScript:**  The tests manipulate V8's internal structures (`Map`, `FieldType`). These structures directly relate to how JavaScript objects are represented and how property accesses are optimized. Changes in JavaScript code can trigger these internal changes.

6. **Construct JavaScript examples:** For the scenarios identified, create simple JavaScript code snippets that would lead to the internal changes being tested in the C++ code. For example, changing an array element from an integer to a floating-point number would trigger an "elements kind reconfiguration". Adding properties with different characteristics demonstrates property transitions.

7. **Organize the summary:** Start with a general statement about the file's purpose. Then, break down the functionality into the logical groups of tests identified earlier. For each group, explain the core concept being tested and provide a corresponding JavaScript example. Emphasize the connection between the C++ tests and the observable behavior in JavaScript.

8. **Refine and clarify:** Review the summary for clarity and accuracy. Ensure the JavaScript examples are simple and illustrative. Use precise language to describe the V8 concepts. Highlight the testing of both standard property transitions and more complex scenarios involving elements kind and prototype changes.

**(Self-correction during the process):**

* **Initial thought:** "This file tests property manipulation in V8."  -> **Correction:** While true, it's more specifically about *field type tracking* and how changes to properties are handled internally.
* **Initial thought:** "The JavaScript examples should be complex to mirror the C++ tests." -> **Correction:** Simpler JavaScript examples are better for demonstrating the *cause* of the internal changes being tested. The complexity is in the V8 internals, not necessarily the triggering JavaScript code.
* **Missed connection:** Initially focused too much on the internal V8 concepts without clearly linking them to observable JavaScript behavior. -> **Correction:** Explicitly adding the "How does this relate to JavaScript?" section and providing examples strengthens the explanation.
这是 `v8/test/cctest/test-field-type-tracking.cc` 文件的第二部分，它延续了第一部分的功能，主要目的是测试 V8 引擎中**字段类型跟踪 (field type tracking)** 的功能。

具体来说，这部分测试的代码主要关注以下几个方面：

**1. 属性重配置 (Reconfigure Property):**

* **测试将数据属性重新配置为访问器常量 (ReconfigureDataFieldAttribute_AccConstantToDataFieldAfterTargetMap):**  测试在目标 Map 之后，将一个数据属性重新配置为一个访问器常量是否能正确处理。这涉及到 V8 如何处理属性类型的改变以及相关的 Map 转换。
* **测试元素类型重配置 (Reconfigure Elements Kind):**  这是一系列更详细的测试，专注于在对象元素类型发生变化时，V8 如何跟踪和更新字段类型。
    * **原地字段泛化 (Generalize Field In Place):**  测试当一个 Map 的元素类型发生变化时，例如从 `PACKED_SMI_ELEMENTS` 变为 `PACKED_ELEMENTS`，是否能正确地将其他分支上的相同字段进行泛化，例如将 `Smi` 类型的字段泛化为 `Double` 或 `Tagged` 类型。
    * **测试不同的字段类型泛化场景:**  涵盖了 `Smi` 到 `Double`，`Smi` 到 `Tagged`，`Double` 到 `Tagged`，以及 `HeapObject` 到 `HeapObject` 和 `HeapObject` 到 `Tagged` 的泛化情况。
    * **测试了常量属性的泛化:**  涵盖了 `const` 和 `mutable` 属性在元素类型重配置时的泛化行为。
    * **测试了字段拥有者的依赖性:** 验证了当字段的类型或表示发生变化时，依赖于该字段的代码是否会被正确地去优化 (deoptimization)。

**2. 分裂 Map 的废弃 (Split Map Deprecation):**

* **测试分裂 Map 转换溢出 (ReconfigurePropertySplitMapTransitionsOverflow):**  测试当一个 Map 因为属性重配置而分裂成两个 Map，并且其中一个 Map 的转换次数达到上限时，V8 如何处理旧 Map 的废弃和新 Map 的创建。

**3. 特殊转换 (Special Transitions):**

* **测试带有特殊转换的字段泛化 (TestGeneralizeFieldWithSpecialTransition):**  测试在进行一些特殊操作（例如元素类型转换、标记为不可扩展、原型链变更等）导致 Map 发生特殊转换后，字段的泛化是否能正确传播到转换后的 Map。
    * **测试了元素类型转换作为特殊转换:** 涵盖了从拥有描述符和不拥有描述符的 Map 进行元素类型转换的情况。
    * **测试了原型转换作为特殊转换:**  涵盖了从拥有描述符和不拥有描述符的 Map 进行原型转换的情况。  这部分代码还区分了 `v8_flags.move_prototype_transitions_first` 的情况，说明 V8 在不同配置下原型转换的处理方式可能有所不同。

**4. 更高层次的转换机制 (Higher Level Transitioning Mechanics):**

* **测试各种属性类型的转换:** 使用 `TransitionToDataFieldOperator`, `TransitionToDataConstantOperator`, `TransitionToAccessorConstantOperator` 等结构体来模拟和测试将属性转换为不同类型的场景，例如数据字段、数据常量和访问器常量。
* **测试属性的重新配置:** 使用 `ReconfigureAsDataPropertyOperator` 和 `ReconfigureAsAccessorPropertyOperator` 来测试重新配置现有属性的类型和属性。
* **定义了不同的检查器 (Checkers):**  例如 `FieldGeneralizationChecker`, `SameMapChecker`, `PropertyKindReconfigurationChecker`，用于验证在不同转换场景下，Map 的状态是否符合预期。

**与 JavaScript 的关系和示例:**

这些测试直接关系到 JavaScript 对象的属性和数组的行为。以下是一些 JavaScript 示例，它们可能会触发这些 C++ 代码中测试的内部机制：

**1. 属性重配置:**

```javascript
const obj = {};
obj.x = 1; // 初始为 SMI 类型的字段

// 重新配置属性 x 为一个访问器
Object.defineProperty(obj, 'x', {
  get: function() { return 2; }
});

// 或者改变属性的类型
obj.x = 1.5; // 将 x 的类型从 SMI 变为 Double
```

**2. 元素类型重配置:**

```javascript
const arr = [1, 2, 3]; // 初始为 PACKED_SMI_ELEMENTS

arr.push(1.5); // 触发元素类型从 PACKED_SMI_ELEMENTS 到 PACKED_DOUBLE_ELEMENTS 的转换

const arr2 = [1, 2, 3];
arr2.push({}); // 触发元素类型到 PACKED_ELEMENTS 的转换
```

**3. 分裂 Map 的废弃:**

这部分很难直接用简单的 JavaScript 代码触发，因为它涉及到 V8 内部的 Map 结构优化和转换机制。但是，频繁地添加和修改对象的属性可能会导致 Map 的分裂。

**4. 特殊转换:**

```javascript
const obj = { a: 1 };
Object.preventExtensions(obj); // 触发不可扩展的转换

const obj2 = { a: 1 };
Object.seal(obj2); // 触发密封的转换

const obj3 = { a: 1 };
Object.freeze(obj3); // 触发冻结的转换

function Parent() {}
function Child() {}
Child.prototype = new Parent();
const child = new Child(); // 触发原型转换
```

**总结来说，这部分 C++ 代码通过各种精细的测试用例，验证了 V8 引擎在处理 JavaScript 对象属性和数组的动态变化时，其字段类型跟踪机制的正确性和效率。这些测试确保了 V8 能够有效地进行类型推断和优化，从而提高 JavaScript 代码的执行性能。**

Prompt: 
```
这是目录为v8/test/cctest/test-field-type-tracking.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
   }
  };

  TestConfig config;
  if (IS_ACCESSOR_FIELD_SUPPORTED) {
    CheckSameMap checker;
    TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
  } else {
    // Currently we have a normalize case.
    CheckNormalize checker;
    TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
  }
}


TEST(ReconfigureDataFieldAttribute_AccConstantToDataFieldAfterTargetMap) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  struct TestConfig {
    Handle<AccessorPair> pair_;
    TestConfig() { pair_ = CreateAccessorPair(true, true); }

    Handle<Map> AddPropertyAtBranch(int branch_id, Expectations* expectations,
                                    Handle<Map> map) {
      CHECK(branch_id == 1 || branch_id == 2);
      if (branch_id == 1) {
        return expectations->AddAccessorConstant(map, NONE, pair_);
      } else {
        Isolate* isolate = CcTest::i_isolate();
        Handle<FieldType> any_type = FieldType::Any(isolate);
        return expectations->AddDataField(map, NONE, PropertyConstness::kConst,
                                          Representation::Smi(), any_type);
      }
    }

    void UpdateExpectations(int property_index, Expectations* expectations) {}
  };

  TestConfig config;
  // These are completely separate branches in transition tree.
  CheckUnrelated checker;
  TestReconfigureProperty_CustomPropertyAfterTargetMap(&config, &checker);
}


////////////////////////////////////////////////////////////////////////////////
// A set of tests for elements kind reconfiguration case.
//

namespace {

// This test ensures that in-place field generalization is correctly propagated
// from one branch of transition tree (|map2|) to another (|map|).
//
//   + - p0 - p1 - p2A - p3 - p4: |map|
//   |
//  ek
//   |
//  {} - p0 - p1 - p2B - p3 - p4: |map2|
//
// where "p2A" and "p2B" differ only in the representation/field type.
//
static void TestReconfigureElementsKind_GeneralizeFieldInPlace(
    const CRFTData& from, const CRFTData& to, const CRFTData& expected) {
  Isolate* isolate = CcTest::i_isolate();

  Expectations expectations(isolate, PACKED_SMI_ELEMENTS);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map =
      isolate->factory()->NewContextfulMapForCurrentContext(
          JS_ARRAY_TYPE, JSArray::kHeaderSize, PACKED_SMI_ELEMENTS);
  initial_map->SetConstructor(*isolate->object_function());

  Handle<Map> map = initial_map;
  map = expectations.AsElementsKind(map, PACKED_ELEMENTS);
  for (int i = 0; i < kPropCount; i++) {
    map = expectations.AddDataField(map, NONE, from.constness,
                                    from.representation, from.type);
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  // Create another branch in transition tree (property at index |kDiffProp|
  // has different attributes), initialize expectations.
  const int kDiffProp = kPropCount / 2;
  Expectations expectations2(isolate, PACKED_SMI_ELEMENTS);

  Handle<Map> map2 = initial_map;
  for (int i = 0; i < kPropCount; i++) {
    if (i == kDiffProp) {
      map2 = expectations2.AddDataField(map2, NONE, to.constness,
                                        to.representation, to.type);
    } else {
      map2 = expectations2.AddDataField(map2, NONE, from.constness,
                                        from.representation, from.type);
    }
  }
  CHECK(!map2->is_deprecated());
  CHECK(map2->is_stable());
  CHECK(expectations2.Check(*map2));

  // Create dummy optimized code object to test correct dependencies
  // on the field owner.
  Handle<Code> code_field_type = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_repr = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_const = CreateDummyOptimizedCode(isolate);
  Handle<Map> field_owner(
      map->FindFieldOwner(isolate, InternalIndex(kDiffProp)), isolate);
  DependentCode::InstallDependency(isolate, code_field_type, field_owner,
                                   DependentCode::kFieldTypeGroup);
  DependentCode::InstallDependency(isolate, code_field_repr, field_owner,
                                   DependentCode::kFieldRepresentationGroup);
  DependentCode::InstallDependency(isolate, code_field_const, field_owner,
                                   DependentCode::kFieldConstGroup);
  CHECK(!code_field_type->marked_for_deoptimization());
  CHECK(!code_field_repr->marked_for_deoptimization());
  CHECK(!code_field_const->marked_for_deoptimization());

  // Reconfigure elements kinds of |map2|, which should generalize
  // representations in |map|.
  DirectHandle<Map> new_map =
      MapUpdater{isolate, map2}.ReconfigureElementsKind(PACKED_ELEMENTS);

  // |map2| should be left unchanged but marked unstable.
  CHECK(!map2->is_stable());
  CHECK(!map2->is_deprecated());
  CHECK_NE(*map2, *new_map);
  CHECK(expectations2.Check(*map2));

  // In case of in-place generalization |map| should be returned as a result of
  // the elements kind reconfiguration, respective field types should be
  // generalized and respective code dependencies should be invalidated.
  // |map| should be NOT deprecated and it should match new expectations.
  expectations.SetDataField(kDiffProp, expected.constness,
                            expected.representation, expected.type);
  CHECK(!map->is_deprecated());
  CHECK_EQ(*map, *new_map);
  CHECK_EQ(IsGeneralizableTo(to.constness, from.constness),
           !code_field_const->marked_for_deoptimization());
  CheckCodeObjectForDeopt(from, expected, code_field_type, code_field_repr,
                          Handle<Code>(), false);

  CHECK(!new_map->is_deprecated());
  CHECK(expectations.Check(*new_map));

  Handle<Map> updated_map = Map::Update(isolate, map);
  CHECK_EQ(*new_map, *updated_map);

  // Ensure Map::FindElementsKindTransitionedMap() is able to find the
  // transitioned map.
  {
    Handle<Map> map_list[1]{updated_map};
    Tagged<Map> transitioned_map = map2->FindElementsKindTransitionedMap(
        isolate, map_list, ConcurrencyMode::kSynchronous);
    CHECK_EQ(*updated_map, transitioned_map);
  }
}

}  // namespace

TEST(ReconfigureElementsKind_GeneralizeSmiFieldToDouble) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type});
}

TEST(ReconfigureElementsKind_GeneralizeSmiFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});
}

TEST(ReconfigureElementsKind_GeneralizeDoubleFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});
}

TEST(ReconfigureElementsKind_GeneralizeHeapObjFieldToHeapObj) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<FieldType> current_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  Handle<FieldType> new_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  Handle<FieldType> expected_type = any_type;

  // Check generalizations that trigger deopts.
  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::HeapObject(), current_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kConst, Representation::HeapObject(), expected_type});

  // PropertyConstness::kConst to PropertyConstness::kMutable migration does
  // not create a new map, therefore trivial generalization.
  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::HeapObject(), current_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::HeapObject(), current_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::HeapObject(), current_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(),
       expected_type});
  current_type = expected_type;

  // Check generalizations that do not trigger deopts.
  new_type = FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type});

  // PropertyConstness::kConst to PropertyConstness::kMutable migration does
  // not create a new map, therefore trivial generalization.
  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), new_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type});
}

TEST(ReconfigureElementsKind_GeneralizeHeapObjectFieldToTagged) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});

  TestReconfigureElementsKind_GeneralizeFieldInPlace(
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type});
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests checking split map deprecation.
//

TEST(ReconfigurePropertySplitMapTransitionsOverflow) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount; i++) {
    map = expectations.AddDataField(map, NONE, PropertyConstness::kMutable,
                                    Representation::Smi(), any_type);
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());

  // Generalize representation of property at index |kSplitProp|.
  const int kSplitProp = kPropCount / 2;
  DirectHandle<Map> split_map;
  Handle<Map> map2 = initial_map;
  {
    for (int i = 0; i < kSplitProp + 1; i++) {
      if (i == kSplitProp) {
        split_map = map2;
      }

      DirectHandle<String> name = CcTest::MakeName("prop", i);
      MaybeHandle<Map> target = TransitionsAccessor::SearchTransition(
          isolate, map2, *name, PropertyKind::kData, NONE);
      CHECK(!target.is_null());
      map2 = target.ToHandleChecked();
    }

    map2 = ReconfigureProperty(isolate, map2, InternalIndex(kSplitProp),
                               PropertyKind::kData, NONE,
                               Representation::Double(), any_type);
    expectations.SetDataField(kSplitProp, PropertyConstness::kMutable,
                              Representation::Double(), any_type);

    CHECK(expectations.Check(*split_map, kSplitProp));
    CHECK(expectations.Check(*map2, kSplitProp + 1));
  }

  // At this point |map| should be deprecated and disconnected from the
  // transition tree.
  CHECK(map->is_deprecated());
  CHECK(!split_map->is_deprecated());
  CHECK(map2->is_stable());
  CHECK(!map2->is_deprecated());

  // Fill in transition tree of |map2| so that it can't have more transitions.
  for (int i = 0; i < TransitionsAccessor::kMaxNumberOfTransitions; i++) {
    CHECK(TransitionsAccessor::CanHaveMoreTransitions(isolate, map2));
    Handle<String> name = CcTest::MakeName("foo", i);
    Map::CopyWithField(isolate, map2, name, any_type, NONE,
                       PropertyConstness::kMutable, Representation::Smi(),
                       INSERT_TRANSITION)
        .ToHandleChecked();
  }
  CHECK(!TransitionsAccessor::CanHaveMoreTransitions(isolate, map2));

  // Try to update |map|, since there is no place for propX transition at |map2|
  // |map| should become normalized.
  DirectHandle<Map> updated_map = Map::Update(isolate, map);

  CheckNormalize checker;
  checker.Check(isolate, map2, updated_map, expectations);
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests involving special transitions (such as elements kind
// transition, observed transition or prototype transition).
//
// This test ensures that field generalization is correctly propagated from one
// branch of transition tree (|map2|) to another (|map|).
//
//                            p4B: |map_b|
//                             ^
//                             |
//                             * - special transition
//                             |
//  {} - p0 - p1 - p2A - p3 - p4A: |map_a|
//
// where "p4A" and "p4B" are exactly the same properties.
//
// UpdateDirectionCheck::kFwd checks if updates to map_a propagate to map_b,
// whereas UpdateDirectionCheck::kBwd checks if updates to map_b propagate back
// to map_a.
//
enum class UpdateDirectionCheck { kFwd, kBwd };
template <typename TestConfig>
static void TestGeneralizeFieldWithSpecialTransition(
    TestConfig* config, const CRFTData& from, const CRFTData& to,
    const CRFTData& expected, ChangeAlertMechanism expected_alert,
    UpdateDirectionCheck direction = UpdateDirectionCheck::kFwd) {
  if (!v8_flags.move_prototype_transitions_first) return;
  Isolate* isolate = CcTest::i_isolate();

  Expectations expectations_a(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> map_a = Map::Create(isolate, 0);
  for (int i = 0; i < kPropCount; i++) {
    map_a = expectations_a.AddDataField(map_a, NONE, from.constness,
                                        from.representation, from.type);
  }
  CHECK(!map_a->is_deprecated());
  CHECK(map_a->is_stable());
  CHECK(expectations_a.Check(*map_a));

  Expectations expectations_b = expectations_a;

  // Apply some special transition to |map|.
  CHECK(map_a->owns_descriptors());
  Handle<Map> map_b = config->Transition(map_a, &expectations_b);

  // |map| should still match expectations.
  CHECK(!map_a->is_deprecated());
  CHECK(expectations_a.Check(*map_a));

  CHECK(!map_b->is_deprecated());
  CHECK(map_b->is_stable());
  CHECK(expectations_b.Check(*map_b));

  // Create dummy optimized code object to test correct dependencies
  // on the field owner.
  Handle<Code> code_field_type = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_repr = CreateDummyOptimizedCode(isolate);
  Handle<Code> code_field_const = CreateDummyOptimizedCode(isolate);
  Handle<Map> field_owner(
      (direction == UpdateDirectionCheck::kFwd ? map_b : map_a)
          ->FindFieldOwner(isolate, InternalIndex(0)),
      isolate);
  DependentCode::InstallDependency(isolate, code_field_type, field_owner,
                                   DependentCode::kFieldTypeGroup);
  DependentCode::InstallDependency(isolate, code_field_repr, field_owner,
                                   DependentCode::kFieldRepresentationGroup);
  DependentCode::InstallDependency(isolate, code_field_const, field_owner,
                                   DependentCode::kFieldConstGroup);
  CHECK(!code_field_type->marked_for_deoptimization());
  CHECK(!code_field_repr->marked_for_deoptimization());
  CHECK(!code_field_const->marked_for_deoptimization());

  // Create new maps by generalizing representation of propX field.
  Handle<Map> updated_maps[kPropCount];
  for (int i = 0; i < kPropCount; i++) {
    Handle<Map> new_map_a = map_a;
    Handle<Map> new_map_b = map_b;
    Handle<Map> map_to_change =
        direction == UpdateDirectionCheck::kFwd ? map_a : map_b;
    Handle<Map> changed_map = ReconfigureProperty(
        isolate, map_to_change, InternalIndex(i), PropertyKind::kData, NONE,
        to.representation, to.type);
    updated_maps[i] = changed_map;

    expectations_a.SetDataField(i, expected.constness, expected.representation,
                                expected.type);
    expectations_b.SetDataField(i, expected.constness, expected.representation,
                                expected.type);

    if (direction == UpdateDirectionCheck::kFwd) {
      new_map_a = changed_map;
      CHECK(expectations_a.Check(*new_map_a));
    } else {
      new_map_b = changed_map;
      CHECK(expectations_b.Check(*new_map_b));
    }

    // Prototype transitions are always moved to the front. Thus both
    // branches are independent since we have two independent property
    // owners in each branch. However on UpdatePrototype we do propagate
    // field types between the branches. Thus we need to call the MapUpdater
    // once more for the changes to propagate.
    if (new_map_a->prototype() != new_map_b->prototype()) {
      Expectations tmp = expectations_a;
      config->Transition(new_map_a, &tmp);
      // TODO(olivf) Prototype transitions do not propagate any changes back to
      // their "true" root map.
      DCHECK_EQ(direction, UpdateDirectionCheck::kFwd);
    }

    switch (expected_alert) {
      case kDeprecation: {
        CHECK(map_to_change->is_deprecated());

        CHECK_NE(*map_to_change, *changed_map);
        CHECK(i == 0 || updated_maps[i - 1]->is_deprecated());

        DirectHandle<Map> changed_map2 = Map::Update(isolate, map_to_change);
        CHECK_EQ(*changed_map, *changed_map2);

        new_map_a = Map::Update(isolate, new_map_a);
        new_map_b = Map::Update(isolate, new_map_b);

        CHECK(!new_map_a->is_deprecated());
        CHECK(!new_map_a->is_dictionary_map());
        CHECK(!new_map_b->is_deprecated());
        CHECK(!new_map_b->is_dictionary_map());

        // If Map::TryUpdate() manages to succeed the result must match the
        // result of Map::Update().
        Handle<Map> tmp_map;
        CHECK(Map::TryUpdate(isolate, map_a).ToHandle(&tmp_map));
        CHECK_EQ(*new_map_a, *tmp_map);
        CHECK(Map::TryUpdate(isolate, map_b).ToHandle(&tmp_map));
        CHECK_EQ(*new_map_b, *tmp_map);

        CHECK(expectations_a.Check(*new_map_a));
        CHECK(expectations_b.Check(*new_map_b));
        CHECK(!IsUndefined(new_map_b->GetBackPointer(), isolate));
        break;
      }
      case kFieldOwnerDependency: {
        CHECK(!map_a->is_deprecated());
        CHECK_EQ(*map_a, *new_map_a);
        CHECK_NE(*map_a, *new_map_b);

        CHECK(!map_b->is_deprecated());
        CHECK_EQ(*map_b, *new_map_b);
        CHECK_NE(*map_b, *new_map_a);

        CHECK(expectations_b.Check(*new_map_b));
        CHECK(expectations_a.Check(*new_map_a));
        break;
      }
      case kNoAlert:
        UNREACHABLE();
        break;
    }
  }

  CheckCodeObjectForDeopt(from, expected, code_field_type, code_field_repr,
                          code_field_const,
                          expected_alert == kFieldOwnerDependency);

  DirectHandle<Map> active_map = updated_maps[kPropCount - 1];
  Handle<Map> old_map = direction == UpdateDirectionCheck::kFwd ? map_a : map_b;
  CHECK(!active_map->is_deprecated());
  // Update all deprecated maps and check that they are now the same.
  DirectHandle<Map> updated_map = Map::Update(isolate, old_map);
  CHECK_EQ(*active_map, *updated_map);
  CheckMigrationTarget(isolate, *map_a, *updated_map);
  for (int i = 0; i < kPropCount; i++) {
    updated_map = Map::Update(isolate, updated_maps[i]);
    CHECK_EQ(*active_map, *updated_map);
    CheckMigrationTarget(isolate, *updated_maps[i], *updated_map);
  }
}

template <typename TestConfig>
void TestMultipleElementsKindTransitions(Isolate* isolate, TestConfig* config,
                                         UpdateDirectionCheck direction) {
  Handle<FieldType> value_type(
      FieldType::Class(Map::Create(isolate, 0), isolate));
  Handle<FieldType> any_type(FieldType::Any(isolate));

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency, direction);

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency, direction);

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), value_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation, direction);
}

TEST(ElementsKindTransitionFromMapOwningDescriptor) {
  if (!v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  struct TestConfig {
    TestConfig(PropertyAttributes attributes, Handle<Symbol> symbol,
               ElementsKind kind)
        : attributes(attributes), symbol(symbol), elements_kind(kind) {}

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      expectations->SetElementsKind(elements_kind);
      expectations->ChangeAttributesForAllProperties(attributes);
      return Map::CopyForPreventExtensions(CcTest::i_isolate(), map, attributes,
                                           symbol, "CopyForPreventExtensions");
    }

    PropertyAttributes attributes;
    Handle<Symbol> symbol;
    ElementsKind elements_kind;
  };
  Factory* factory = isolate->factory();
  TestConfig configs[] = {
      {FROZEN, factory->frozen_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_FROZEN_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {SEALED, factory->sealed_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_SEALED_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {NONE, factory->nonextensible_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind
           ? HOLEY_NONEXTENSIBLE_ELEMENTS
           : DICTIONARY_ELEMENTS}};

  for (auto& direction :
       {UpdateDirectionCheck::kFwd, UpdateDirectionCheck::kBwd}) {
    for (size_t i = 0; i < arraysize(configs); i++) {
      TestMultipleElementsKindTransitions(isolate, &configs[i], direction);
    }
  }
}

TEST(ElementsKindTransitionFromMapNotOwningDescriptor) {
  if (!v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  struct TestConfig {
    TestConfig(PropertyAttributes attributes, Handle<Symbol> symbol,
               ElementsKind kind)
        : attributes(attributes), symbol(symbol), elements_kind(kind) {}

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      CHECK(map->owns_descriptors());
      Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                         NONE, PropertyConstness::kMutable,
                         Representation::Smi(), INSERT_TRANSITION)
          .ToHandleChecked();
      CHECK(!map->owns_descriptors());

      expectations->SetElementsKind(elements_kind);
      expectations->ChangeAttributesForAllProperties(attributes);
      return Map::CopyForPreventExtensions(isolate, map, attributes, symbol,
                                           "CopyForPreventExtensions");
    }

    PropertyAttributes attributes;
    Handle<Symbol> symbol;
    ElementsKind elements_kind;
  };
  Factory* factory = isolate->factory();
  TestConfig configs[] = {
      {FROZEN, factory->frozen_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_FROZEN_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {SEALED, factory->sealed_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_SEALED_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {NONE, factory->nonextensible_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind
           ? HOLEY_NONEXTENSIBLE_ELEMENTS
           : DICTIONARY_ELEMENTS}};

  for (auto& direction :
       {UpdateDirectionCheck::kFwd, UpdateDirectionCheck::kBwd}) {
    for (size_t i = 0; i < arraysize(configs); i++) {
      TestMultipleElementsKindTransitions(isolate, &configs[i], direction);
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests for the prototype transition case.
//
// This test ensures that field generalization is correctly propagated across an
// UpdatePrototype transition.
//
// In the case of prototype transitions the transition tree is actually
// reshaped as:
//
//  {} - p0B - p1B - p2B - p3B - p4B: |map_b|
//  ^
//  |
//  * - prototype transition
//  |
//  {} - p0A - p1A - p2A - p3A - p4A: |map_a|
//
//  And the updates go via the MapUpdater. Thus generalizations from map_a to
//  map_b happen during UpdatePrototype, (i.e., on the transition of the next
//  object).
//
// By design updates currently only happen in forward direction, i.e., changes
// to map_a are propagated to map_b, but not the inverse.

template <typename TestConfig>
void TestMultiplePrototypeTransitions(Isolate* isolate, TestConfig* config) {
  Handle<FieldType> value_type(
      FieldType::Class(Map::Create(isolate, 0), isolate));
  Handle<FieldType> any_type(FieldType::Any(isolate));

  // Smi + HeapObject -> Tagged

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  // HeapObject + HeapObject -> Tagged

  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config,
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), any_type},
      kFieldOwnerDependency);

  // Double + HeapObject -> Tagged

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), any_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kConst, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  // Smi + Double -> Double

  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kConst, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      kDeprecation);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kConst, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
  TestGeneralizeFieldWithSpecialTransition(
      config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      kDeprecation);
}

TEST(PrototypeTransitionFromMapOwningDescriptor) {
  if (!v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      MapUpdater update(CcTest::i_isolate(), map);
      return update.ApplyPrototypeTransition(prototype_);
    }
  } config;

  TestMultiplePrototypeTransitions(isolate, &config);
}

TEST(PrototypeTransitionFromMapNotOwningDescriptor) {
  if (!v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      if (map->owns_descriptors()) {
        Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                           NONE, PropertyConstness::kMutable,
                           Representation::Smi(), INSERT_TRANSITION)
            .ToHandleChecked();
      }
      CHECK(!map->owns_descriptors());

      MapUpdater update(isolate, map);
      return update.ApplyPrototypeTransition(prototype_);
    }
  } config;

  TestMultiplePrototypeTransitions(isolate, &config);
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests involving special transitions (such as elements kind
// transition, observed transition or prototype transition).
//
// The following legacy tests are for when
// !v8_flags.move_prototype_transitions_first

// This test ensures that field generalization is correctly propagated from one
// branch of transition tree (|map2|) to another (|map|).
//
//                            p4B: |map2|
//                             |
//                             * - special transition
//                             |
//  {} - p0 - p1 - p2A - p3 - p4A: |map|
//
// where "p4A" and "p4B" are exactly the same properties.
//
// TODO(ishell): unify this test template with
// TestReconfigureDataFieldAttribute_GeneralizeField once
// IS_PROTO_TRANS_ISSUE_FIXED and IS_NON_EQUIVALENT_TRANSITION_SUPPORTED are
// fixed.
template <typename TestConfig>
static void TestGeneralizeFieldWithSpecialTransitionLegacy(
    TestConfig* config, const CRFTData& from, const CRFTData& to,
    const CRFTData& expected, ChangeAlertMechanism expected_alert) {
  if (v8_flags.move_prototype_transitions_first) return;

  Isolate* isolate = CcTest::i_isolate();

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount; i++) {
    map = expectations.AddDataField(map, NONE, from.constness,
                                    from.representation, from.type);
  }
  CHECK(!map->is_deprecated());
  CHECK(map->is_stable());
  CHECK(expectations.Check(*map));

  Expectations expectations2 = expectations;

  // Apply some special transition to |map|.
  CHECK(map->owns_descriptors());
  Handle<Map> map2 = config->Transition(map, &expectations2);

  // |map| should still match expectations.
  CHECK(!map->is_deprecated());
  CHECK(expectations.Check(*map));

  if (config->generalizes_representations()) {
    for (int i = 0; i < kPropCount; i++) {
      expectations2.GeneralizeField(i);
    }
  }

  CHECK(!map2->is_deprecated());
  CHECK(map2->is_stable());
  CHECK(expectations2.Check(*map2));

  // Create new maps by generalizing representation of propX field.
  Handle<Map> maps[kPropCount];
  for (int i = 0; i < kPropCount; i++) {
    Handle<Map> new_map =
        ReconfigureProperty(isolate, map, InternalIndex(i), PropertyKind::kData,
                            NONE, to.representation, to.type);
    maps[i] = new_map;

    expectations.SetDataField(i, expected.constness, expected.representation,
                              expected.type);

    switch (expected_alert) {
      case kDeprecation: {
        CHECK(map->is_deprecated());
        CHECK_NE(*map, *new_map);
        CHECK(i == 0 || maps[i - 1]->is_deprecated());
        CHECK(expectations.Check(*new_map));

        DirectHandle<Map> new_map2 = Map::Update(isolate, map2);
        CHECK(!new_map2->is_deprecated());
        CHECK(!new_map2->is_dictionary_map());

        Handle<Map> tmp_map;
        if (Map::TryUpdate(isolate, map2).ToHandle(&tmp_map)) {
          // If Map::TryUpdate() manages to succeed the result must match the
          // result of Map::Update().
          CHECK_EQ(*new_map2, *tmp_map);
        } else {
          // Equivalent transitions should always find the updated map.
          CHECK(config->is_non_equivalent_transition());
        }

        if (config->is_non_equivalent_transition()) {
          // In case of non-equivalent transition currently we generalize all
          // representations.
          for (int j = 0; j < kPropCount; j++) {
            expectations2.GeneralizeField(j);
          }
          CHECK(IsUndefined(new_map2->GetBackPointer(), isolate));
          CHECK(expectations2.Check(*new_map2));
        } else {
          expectations2.SetDataField(i, expected.constness,
                                     expected.representation, expected.type);

          CHECK(!IsUndefined(new_map2->GetBackPointer(), isolate));
          CHECK(expectations2.Check(*new_map2));
        }
        break;
      }
      case kFieldOwnerDependency: {
        CHECK(!map->is_deprecated());
        // TODO(ishell): Review expectations once IS_PROTO_TRANS_ISSUE_FIXED is
        // removed.
        CHECK(!IS_PROTO_TRANS_ISSUE_FIXED);
        CHECK_EQ(*map, *new_map);
        CHECK(expectations.Check(*new_map));

        CHECK(!map2->is_deprecated());
        CHECK_NE(*map2, *new_map);
        expectations2.SetDataField(i, expected.constness,
                                   expected.representation, expected.type);
        CHECK(expectations2.Check(*map2));
        break;
      }
      case kNoAlert:
        UNREACHABLE();
        break;
    }
  }

  DirectHandle<Map> active_map = maps[kPropCount - 1];
  CHECK(!active_map->is_deprecated());

  // Update all deprecated maps and check that they are now the same.
  DirectHandle<Map> updated_map = Map::Update(isolate, map);
  CHECK_EQ(*active_map, *updated_map);
  CheckMigrationTarget(isolate, *map, *updated_map);
  for (int i = 0; i < kPropCount; i++) {
    updated_map = Map::Update(isolate, maps[i]);
    CHECK_EQ(*active_map, *updated_map);
    CheckMigrationTarget(isolate, *maps[i], *updated_map);
  }
}

TEST(ElementsKindTransitionFromMapOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    TestConfig(PropertyAttributes attributes, Handle<Symbol> symbol,
               ElementsKind kind)
        : attributes(attributes), symbol(symbol), elements_kind(kind) {}

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      expectations->SetElementsKind(elements_kind);
      expectations->ChangeAttributesForAllProperties(attributes);
      return Map::CopyForPreventExtensions(CcTest::i_isolate(), map, attributes,
                                           symbol, "CopyForPreventExtensions");
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const { return false; }
    bool is_non_equivalent_transition() const { return false; }

    PropertyAttributes attributes;
    Handle<Symbol> symbol;
    ElementsKind elements_kind;
  };
  Factory* factory = isolate->factory();
  TestConfig configs[] = {
      {FROZEN, factory->frozen_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_FROZEN_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {SEALED, factory->sealed_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_SEALED_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {NONE, factory->nonextensible_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind
           ? HOLEY_NONEXTENSIBLE_ELEMENTS
           : DICTIONARY_ELEMENTS}};
  for (size_t i = 0; i < arraysize(configs); i++) {
    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Smi(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);

    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Double(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);
  }
}

TEST(ElementsKindTransitionFromMapNotOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    TestConfig(PropertyAttributes attributes, Handle<Symbol> symbol,
               ElementsKind kind)
        : attributes(attributes), symbol(symbol), elements_kind(kind) {}

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      CHECK(map->owns_descriptors());
      Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                         NONE, PropertyConstness::kMutable,
                         Representation::Smi(), INSERT_TRANSITION)
          .ToHandleChecked();
      CHECK(!map->owns_descriptors());

      expectations->SetElementsKind(elements_kind);
      expectations->ChangeAttributesForAllProperties(attributes);
      return Map::CopyForPreventExtensions(isolate, map, attributes, symbol,
                                           "CopyForPreventExtensions");
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const { return false; }
    bool is_non_equivalent_transition() const { return false; }

    PropertyAttributes attributes;
    Handle<Symbol> symbol;
    ElementsKind elements_kind;
  };
  Factory* factory = isolate->factory();
  TestConfig configs[] = {
      {FROZEN, factory->frozen_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_FROZEN_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {SEALED, factory->sealed_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind ? HOLEY_SEALED_ELEMENTS
                                                   : DICTIONARY_ELEMENTS},
      {NONE, factory->nonextensible_symbol(),
       v8_flags.enable_sealed_frozen_elements_kind
           ? HOLEY_NONEXTENSIBLE_ELEMENTS
           : DICTIONARY_ELEMENTS}};
  for (size_t i = 0; i < arraysize(configs); i++) {
    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Smi(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);

    TestGeneralizeFieldWithSpecialTransition(
        &configs[i],
        {PropertyConstness::kMutable, Representation::Double(), any_type},
        {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
        {PropertyConstness::kMutable, Representation::Tagged(), any_type},
        kFieldOwnerDependency);
  }
}

TEST(PrototypeTransitionFromMapOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      return Map::TransitionToUpdatePrototype(CcTest::i_isolate(), map,
                                              prototype_);
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const {
      return !IS_PROTO_TRANS_ISSUE_FIXED;
    }
    bool is_non_equivalent_transition() const { return true; }
  };
  TestConfig config;
  TestGeneralizeFieldWithSpecialTransition(
      &config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      &config,
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

TEST(PrototypeTransitionFromMapNotOwningDescriptorLegacy) {
  if (v8_flags.move_prototype_transitions_first) return;
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);
  Handle<FieldType> value_type =
      FieldType::Class(Map::Create(isolate, 0), isolate);

  struct TestConfig {
    Handle<JSObject> prototype_;

    TestConfig() {
      Isolate* isolate = CcTest::i_isolate();
      Factory* factory = isolate->factory();
      prototype_ = factory->NewJSObjectFromMap(Map::Create(isolate, 0));
    }

    Handle<Map> Transition(Handle<Map> map, Expectations* expectations) {
      Isolate* isolate = CcTest::i_isolate();
      Handle<FieldType> any_type = FieldType::Any(isolate);

      // Add one more transition to |map| in order to prevent descriptors
      // ownership.
      CHECK(map->owns_descriptors());
      Map::CopyWithField(isolate, map, CcTest::MakeString("foo"), any_type,
                         NONE, PropertyConstness::kMutable,
                         Representation::Smi(), INSERT_TRANSITION)
          .ToHandleChecked();
      CHECK(!map->owns_descriptors());

      return Map::TransitionToUpdatePrototype(isolate, map, prototype_);
    }
    // TODO(ishell): remove once IS_PROTO_TRANS_ISSUE_FIXED is removed.
    bool generalizes_representations() const {
      return !IS_PROTO_TRANS_ISSUE_FIXED;
    }
    bool is_non_equivalent_transition() const { return true; }
  };
  TestConfig config;
  TestGeneralizeFieldWithSpecialTransition(
      &config, {PropertyConstness::kMutable, Representation::Smi(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);

  TestGeneralizeFieldWithSpecialTransition(
      &config,
      {PropertyConstness::kMutable, Representation::Double(), any_type},
      {PropertyConstness::kMutable, Representation::HeapObject(), value_type},
      {PropertyConstness::kMutable, Representation::Tagged(), any_type},
      kFieldOwnerDependency);
}

////////////////////////////////////////////////////////////////////////////////
// A set of tests for higher level transitioning mechanics.
//

struct TransitionToDataFieldOperator {
  PropertyConstness constness_;
  Representation representation_;
  PropertyAttributes attributes_;
  Handle<FieldType> heap_type_;
  Handle<Object> value_;

  TransitionToDataFieldOperator(PropertyConstness constness,
                                Representation representation,
                                Handle<FieldType> heap_type,
                                Handle<Object> value,
                                PropertyAttributes attributes = NONE)
      : constness_(constness),
        representation_(representation),
        attributes_(attributes),
        heap_type_(heap_type),
        value_(value) {}

  Handle<Map> DoTransition(Expectations* expectations, Handle<Map> map) {
    return expectations->TransitionToDataField(
        map, attributes_, constness_, representation_, heap_type_, value_);
  }
};


struct TransitionToDataConstantOperator {
  PropertyAttributes attributes_;
  Handle<JSFunction> value_;

  TransitionToDataConstantOperator(Handle<JSFunction> value,
                                   PropertyAttributes attributes = NONE)
      : attributes_(attributes), value_(value) {}

  Handle<Map> DoTransition(Expectations* expectations, Handle<Map> map) {
    return expectations->TransitionToDataConstant(map, attributes_, value_);
  }
};


struct TransitionToAccessorConstantOperator {
  PropertyAttributes attributes_;
  Handle<AccessorPair> pair_;

  TransitionToAccessorConstantOperator(Handle<AccessorPair> pair,
                                       PropertyAttributes attributes = NONE)
      : attributes_(attributes), pair_(pair) {}

  Handle<Map> DoTransition(Expectations* expectations, Handle<Map> map) {
    return expectations->TransitionToAccessorConstant(map, attributes_, pair_);
  }
};


struct ReconfigureAsDataPropertyOperator {
  InternalIndex descriptor_;
  Representation representation_;
  PropertyAttributes attributes_;
  Handle<FieldType> heap_type_;

  ReconfigureAsDataPropertyOperator(int descriptor,
                                    Representation representation,
                                    Handle<FieldType> heap_type,
                                    PropertyAttributes attributes = NONE)
      : descriptor_(descriptor),
        representation_(representation),
        attributes_(attributes),
        heap_type_(heap_type) {}

  Handle<Map> DoTransition(Isolate* isolate, Expectations* expectations,
                           Handle<Map> map) {
    expectations->SetDataField(descriptor_.as_int(),
                               PropertyConstness::kMutable, representation_,
                               heap_type_);
    return MapUpdater::ReconfigureExistingProperty(
        isolate, map, descriptor_, PropertyKind::kData, attributes_,
        PropertyConstness::kConst);
  }
};


struct ReconfigureAsAccessorPropertyOperator {
  InternalIndex descriptor_;
  PropertyAttributes attributes_;

  ReconfigureAsAccessorPropertyOperator(int descriptor,
                                        PropertyAttributes attributes = NONE)
      : descriptor_(descriptor), attributes_(attributes) {}

  Handle<Map> DoTransition(Isolate* isolate, Expectations* expectations,
                           Handle<Map> map) {
    expectations->SetAccessorField(descriptor_.as_int());
    return MapUpdater::ReconfigureExistingProperty(
        isolate, map, descriptor_, PropertyKind::kAccessor, attributes_,
        PropertyConstness::kConst);
  }
};

// Checks that field generalization happened.
struct FieldGeneralizationChecker {
  int descriptor_;
  PropertyConstness constness_;
  Representation representation_;
  PropertyAttributes attributes_;
  Handle<FieldType> heap_type_;

  FieldGeneralizationChecker(int descriptor, PropertyConstness constness,
                             Representation representation,
                             Handle<FieldType> heap_type,
                             PropertyAttributes attributes = NONE)
      : descriptor_(descriptor),
        constness_(constness),
        representation_(representation),
        attributes_(attributes),
        heap_type_(heap_type) {}

  void Check(Isolate* isolate, Expectations* expectations, Handle<Map> map1,
             DirectHandle<Map> map2) {
    CHECK(!map2->is_deprecated());

    CHECK(map1->is_deprecated());
    CHECK_NE(*map1, *map2);
    DirectHandle<Map> updated_map = Map::Update(isolate, map1);
    CHECK_EQ(*map2, *updated_map);
    CheckMigrationTarget(isolate, *map1, *updated_map);

    expectations->SetDataField(descriptor_, attributes_, constness_,
                               representation_, heap_type_);
    CHECK(expectations->Check(*map2));
  }
};


// Checks that existing transition was taken as is.
struct SameMapChecker {
  void Check(Isolate* isolate, Expectations* expectations,
             DirectHandle<Map> map1, DirectHandle<Map> map2) {
    CHECK(!map2->is_deprecated());
    CHECK_EQ(*map1, *map2);
    CHECK(expectations->Check(*map2));
  }
};


// Checks that both |map1| and |map2| should stays non-deprecated, this is
// the case when property kind is change.
struct PropertyKindReconfigurationChecker {
  void Check(Expectations* expectations, DirectHandle<Map> map1,
             DirectHandle<Map> map2) {
    CHECK(!map1->is_deprecated());
    CHECK(!map2->is_deprecated());
    CHECK_NE(*map1, *map2);
    CHECK(expectations->Check(*map2));
  }
};


// This test transitions to various property types under different
// circumstances.
// Plan:
// 1) create a |map| with p0..p3 properties.
// 2) create |map1| by adding "p4" to |map0|.
// 3) create |map2| by transition to "p4" from |map0|.
//
//                       + - p4B: |map2|
//                       |
//  {} - p0 - p1 - pA - p3: |map|
//                       |
//                       + - p4A: |map1|
//
// where "p4A" and "p4B" differ only in the attributes.
//
template <typename TransitionOp1, typename TransitionOp2, typename Checker>
static void TestTransitionTo(TransitionOp1* transition_op1,
                             TransitionOp2* transition_op2, Checker* checker) {
  Isolate* isolate = CcTest::i_isolate();
  Handle<FieldType> any_type = FieldType::Any(isolate);

  Expectations expectations(isolate);

  // Create a map, add required properties to it and initialize expectations.
  Handle<Map> initial_map = Map::Create(isolate, 0);
  Handle<Map> map = initial_map;
  for (int i = 0; i < kPropCount - 1; i++) {
    map = expectations.AddDataField(map, NONE, PropertyConstness::kMutable,
                                    Representation::Smi(), any_type);
  }
  CHECK(expectations.Check(*map));

  Expectations expectations1 = expectations;
  Handle<Map> map1 = transition_op1->DoTransition(&expectations1, map);
  CHECK(expectations1.Check(*map1));

  Expectations expectations2 = expectations;
  Handle<Map> map2 = transition_op2->DoTransition(&expectations2, map);

  // Let the test customization do the check.
  checker->Check(isolate, &expectations2, map1, map2);
}

TEST(TransitionDataFieldToDataField) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<Object> value1 = handle(Smi::zero(), isolate);
  TransitionToDataFieldOperator transition_op1(
      PropertyConstness::kMutable, Representation::Smi(), any_type, value1);

  Handle<Object> value2 = isolate->factory()->NewHeapNumber(0);
  TransitionToDataFieldOperator transition_op2(
      PropertyConstness::kMutable, Representation::Double(), any_type, value2);

  FieldGeneralizationChecker checker(kPropCount - 1,
                                     PropertyConstness::kMutable,
                                     Representation::Double(), any_type);
  TestTransitionTo(&transition_op1, &transition_op2, &checker);
}

TEST(TransitionDataConstantToSameDataConstant) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<JSFunction> js_func =
      factory->NewFunctionForTesting(factory->empty_string());
  TransitionToDataConstantOperator transition_op(js_func);

  SameMapChecker checker;
  TestTransitionTo(&transition_op, &transition_op, &checker);
}


TEST(TransitionDataConstantToAnotherDataConstant) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<String> name = factory->empty_string();
  Handle<Map> sloppy_map =
      Map::CopyInitialMap(isolate, isolate->sloppy_function_map());
  Handle<SharedFunctionInfo> info = factory->NewSharedFunctionInfoForBuiltin(
      name, Builtin::kIllegal, 0, kDontAdapt);
  CHECK(sloppy_map->is_stable());

  Handle<JSFunction> js_func1 =
      Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
          .set_map(sloppy_map)
          .Build();
  TransitionToDataConstantOperator transition_op1(js_func1);

  Handle<JSFunction> js_func2 =
      Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
          .set_map(sloppy_map)
          .Build();
  TransitionToDataConstantOperator transition_op2(js_func2);

  SameMapChecker checker;
  TestTransitionTo(&transition_op1, &transition_op2, &checker);
}


TEST(TransitionDataConstantToDataField) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();

  Handle<FieldType> any_type = FieldType::Any(isolate);

  Handle<JSFunction> js_func1 =
      factory->NewFunctionForTesting(factory->empty_string());
  TransitionToDataConstantOperator transition_op1(js_func1);

  Handle<Object> value2 = isolate->factory()->NewHeapNumber(0);
  TransitionToDataFieldOperator transition_op2(
      PropertyConstness::kMutable, Representation::Tagged(), any_type, value2);

  SameMapChecker checker;
  TestTransitionTo(&transition_op1, &transition_op2, &checker);
}


TEST(TransitionAccessorConstantToSameAccessorConstant) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());

  Handle<AccessorPair> pair = CreateAccessorPair(true, true);
  TransitionToAccessorConstantOperator transition_op(pair);

  SameMapChecker checker;
  TestTransitionTo(&transition_op, &transition_op, &checker);
}

// TODO(ishell): add this test once IS_ACCESSOR_FIELD_SUPPORTED is supported.
// TEST(TransitionAccessorConstantToAnotherAccessorConstant)

TEST(HoleyHeapNumber) {
  CcTest::InitializeVM();
  v8::HandleScope scope(CcTest::isolate());
  Isolate* isolate = CcTest::i_isolate();

  auto mhn = isolate->factory()->NewHeapNumberWithHoleNaN();
  CHECK_EQ(kHoleNanInt64, mhn->value_as_bits());

  mhn = isolate->factory()->NewHeapNumber(0.0);
  CHECK_EQ(uint64_t{0}, mhn->value_as_bits());

  mhn->set_value_as_bits(kHoleNanInt64);
  CHECK_EQ(kHoleNanInt64, mhn->value_as_bits());

  // Ensure that new storage for uninitialized value or mutable heap number
  // with uninitialized sentinel (kHoleNanInt64) is a mutable heap number
  // with uninitialized sentinel.
  DirectHandle<Object> obj =
      Object::NewStorageFor(isolate, isolate->factory()->uninitialized_value(),
                            Representation::Double());
  CHECK(IsHeapNumber(*obj));
  CHECK_EQ(kHoleNanInt64, Cast<HeapNumber>(*obj)->value_as_bits());

  obj = Object::NewStorageFor(isolate, mhn, Representation::Double());
  CHECK(IsHeapNumber(*obj));
  CHECK_EQ(kHoleNanInt64, Cast<HeapNumber>(*obj)->value_as_bits());
}

namespace {

te
"""


```