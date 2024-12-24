Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/compiler/load-elimination-unittest.cc`.

This file seems to contain unit tests for a compiler optimization technique called "load elimination".

Load elimination is a compiler optimization that aims to remove redundant load operations (reading data from memory) when the value being loaded is already known.

The tests seem to cover various scenarios involving loading and storing values in memory, specifically focusing on:

1. **Loading the same element twice:** Verifying that the second load can be replaced with the result of the first load.
2. **Storing an element and then loading it:** Checking if the load can be replaced with the stored value.
3. **Interleaving stores and loads:**  Testing if a load can be replaced by the value of the most recent store to the same memory location.
4. **Load elimination across control flow:** Examining how load elimination works in conditional branches (if-else statements).
5. **Handling type mismatches:** Investigating how load elimination behaves when the type of the loaded value doesn't match the stored value.
6. **Impact of "kill" operations:**  Understanding how operations that might invalidate cached values affect load elimination.
7. **Alias analysis and regions:** Exploring load elimination in the context of memory regions and potential aliasing.

To demonstrate the connection with JavaScript, I need to illustrate how these load/store operations and the resulting optimizations might occur in a JavaScript context.
这个C++源代码文件 `v8/test/unittests/compiler/load-elimination-unittest.cc` 是 V8 JavaScript 引擎的一部分，专门用于测试 **负载消除 (Load Elimination)** 编译器优化。

**功能归纳:**

这个文件包含了一系列单元测试，用于验证 `LoadElimination` 编译优化器的正确性和有效性。`LoadElimination` 是一种常见的编译器优化技术，旨在消除代码中冗余的内存加载操作。如果编译器能够确定一个内存位置的值在之前的操作中已经被加载并且没有发生改变，那么后续对该内存位置的加载操作就可以被替换为之前加载的值，从而提高代码执行效率。

这些测试用例覆盖了各种场景，包括：

1. **连续加载相同的元素或字段:** 测试当连续两次加载相同的对象属性或数组元素时，第二次加载是否会被优化为直接使用第一次加载的结果。
2. **先存储后加载:** 测试当先将一个值存储到对象属性或数组元素中，然后立即加载该位置的值时，加载操作是否会被优化为直接使用存储的值。
3. **存储操作之间的加载:** 测试当多个存储操作发生时，加载操作是否能正确地获取最近一次存储的值。
4. **控制流中的加载:** 测试在条件分支语句中，加载操作是否能根据控制流的信息进行优化。
5. **类型不匹配的情况:** 测试当存储的类型与加载的类型不匹配时，负载消除优化器如何处理（例如插入类型检查）。
6. **影响负载消除的操作:** 测试某些操作（如存储到不同的字段或元素）如何影响之前可以被消除的加载操作。
7. **区域 (Region) 和别名分析:** 测试在涉及内存区域和别名分析的场景下，负载消除优化器如何工作。

**与 JavaScript 的关系及示例:**

负载消除是一种通用的编译器优化技术，虽然测试是用 C++ 编写的，但它直接影响 V8 引擎执行 JavaScript 代码的效率。以下是一些 JavaScript 例子，展示了负载消除可能发生的场景：

**示例 1: 连续加载相同的属性**

```javascript
function testLoadElimination(obj) {
  const x = obj.a; // 第一次加载 obj.a
  const y = obj.a; // 第二次加载 obj.a，可能被优化掉
  return x + y;
}

const myObj = { a: 10 };
testLoadElimination(myObj);
```

在上面的例子中，如果 `obj.a` 在两次访问之间没有被修改，那么 V8 的负载消除优化器可能会将第二次加载 `obj.a` 替换为直接使用第一次加载得到的值。

**示例 2: 先存储后加载**

```javascript
function testStoreLoadElimination(arr, index, value) {
  arr[index] = value; // 存储值到数组
  const loadedValue = arr[index]; // 加载刚刚存储的值，可能被优化掉
  return loadedValue;
}

const myArray = [1, 2, 3];
testStoreLoadElimination(myArray, 1, 5); // 返回 5
```

在这个例子中，存储 `arr[index]` 的值后立即加载它。负载消除优化器可能会将加载操作直接替换为之前存储的 `value`。

**示例 3:  条件分支中的加载**

```javascript
function conditionalLoad(obj, condition) {
  let value;
  if (condition) {
    value = obj.b; // 在 true 分支加载
  } else {
    value = obj.b; // 在 false 分支加载
  }
  return value;
}

const myObj2 = { b: 20 };
conditionalLoad(myObj2, true);
```

即使在不同的控制流分支中加载相同的属性，负载消除优化器也可能会尝试进行优化，尤其是在确定 `obj.b` 在两次加载之间没有被修改的情况下。

**总结:**

`v8/test/unittests/compiler/load-elimination-unittest.cc` 文件通过一系列精细的测试用例，确保 V8 引擎的负载消除优化器能够正确且有效地工作，从而提高 JavaScript 代码的执行性能。这些优化对于提升复杂 JavaScript 应用的运行速度至关重要。

Prompt: 
```
这是目录为v8/test/unittests/compiler/load-elimination-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/load-elimination.h"

#include "src/compiler/access-builder.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/node.h"
#include "src/compiler/simplified-operator.h"
#include "test/unittests/compiler/graph-reducer-unittest.h"
#include "test/unittests/compiler/graph-unittest.h"
#include "test/unittests/compiler/node-test-utils.h"

using testing::_;
using testing::StrictMock;

namespace v8 {
namespace internal {
namespace compiler {

class LoadEliminationTest : public TypedGraphTest {
 public:
  LoadEliminationTest()
      : TypedGraphTest(3),
        simplified_(zone()),
        jsgraph_(isolate(), graph(), common(), nullptr, simplified(), nullptr) {
  }
  ~LoadEliminationTest() override = default;

 protected:
  JSGraph* jsgraph() { return &jsgraph_; }
  SimplifiedOperatorBuilder* simplified() { return &simplified_; }

 private:
  SimplifiedOperatorBuilder simplified_;
  JSGraph jsgraph_;
};

TEST_F(LoadEliminationTest, LoadElementAndLoadElement) {
  Node* object = Parameter(Type::Any(), 0);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* index = Parameter(Type::UnsignedSmall(), 1);
  ElementAccess const access = {kTaggedBase, kTaggedSize, Type::Any(),
                                MachineType::AnyTagged(), kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* load1 = effect = graph()->NewNode(simplified()->LoadElement(access),
                                          object, index, effect, control);
  load_elimination.Reduce(load1);

  Node* load2 = effect = graph()->NewNode(simplified()->LoadElement(access),
                                          object, index, effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load2, load1, load1, _));
  Reduction r = load_elimination.Reduce(load2);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load1, r.replacement());
}

TEST_F(LoadEliminationTest, StoreElementAndLoadElement) {
  Node* object = Parameter(Type::Any(), 0);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* index = Parameter(Type::UnsignedSmall(), 1);
  Node* value = Parameter(Type::Any(), 2);
  ElementAccess const access = {kTaggedBase, kTaggedSize, Type::Any(),
                                MachineType::AnyTagged(), kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* store = effect =
      graph()->NewNode(simplified()->StoreElement(access), object, index, value,
                       effect, control);
  load_elimination.Reduce(store);

  Node* load = effect = graph()->NewNode(simplified()->LoadElement(access),
                                         object, index, effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load, value, store, _));
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(value, r.replacement());
}

TEST_F(LoadEliminationTest, StoreElementAndStoreFieldAndLoadElement) {
  Node* object = Parameter(Type::Any(), 0);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  Node* index = Parameter(Type::UnsignedSmall(), 1);
  Node* value = Parameter(Type::Any(), 2);
  ElementAccess const access = {kTaggedBase, kTaggedSize, Type::Any(),
                                MachineType::AnyTagged(), kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* store1 = effect =
      graph()->NewNode(simplified()->StoreElement(access), object, index, value,
                       effect, control);
  load_elimination.Reduce(store1);

  Node* store2 = effect =
      graph()->NewNode(simplified()->StoreField(AccessBuilder::ForMap()),
                       object, value, effect, control);
  load_elimination.Reduce(store2);

  Node* load = effect = graph()->NewNode(simplified()->LoadElement(access),
                                         object, index, effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load, value, store2, _));
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(value, r.replacement());
}

TEST_F(LoadEliminationTest, LoadFieldAndLoadField) {
  Node* object = Parameter(Type::Any(), 0);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess const access = {kTaggedBase,         kTaggedSize,
                              MaybeHandle<Name>(), OptionalMapRef(),
                              Type::Any(),         MachineType::AnyTagged(),
                              kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* load1 = effect = graph()->NewNode(simplified()->LoadField(access),
                                          object, effect, control);
  load_elimination.Reduce(load1);

  Node* load2 = effect = graph()->NewNode(simplified()->LoadField(access),
                                          object, effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load2, load1, load1, _));
  Reduction r = load_elimination.Reduce(load2);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load1, r.replacement());
}

TEST_F(LoadEliminationTest, StoreFieldAndLoadField) {
  Node* object = Parameter(Type::Any(), 0);
  Node* value = Parameter(Type::Any(), 1);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess access = {kTaggedBase,      kTaggedSize, MaybeHandle<Name>(),
                        OptionalMapRef(), Type::Any(), MachineType::AnyTagged(),
                        kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* store = effect = graph()->NewNode(simplified()->StoreField(access),
                                          object, value, effect, control);
  load_elimination.Reduce(store);

  Node* load = effect = graph()->NewNode(simplified()->LoadField(access),
                                         object, effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load, value, store, _));
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(value, r.replacement());
}

TEST_F(LoadEliminationTest, StoreFieldAndKillFields) {
  Node* object = Parameter(Type::Any(), 0);
  Node* value = Parameter(Type::Any(), 1);
  Node* effect = graph()->start();
  Node* control = graph()->start();

  FieldAccess access1 = {kTaggedBase,         kTaggedSize,
                         MaybeHandle<Name>(), OptionalMapRef(),
                         Type::Any(),         MachineType::AnyTagged(),
                         kNoWriteBarrier};

  // Offset that out of field cache size.
  FieldAccess access2 = {kTaggedBase,         2048 * kTaggedSize,
                         MaybeHandle<Name>(), OptionalMapRef(),
                         Type::Any(),         MachineType::AnyTagged(),
                         kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* store1 = effect = graph()->NewNode(simplified()->StoreField(access1),
                                          object, value, effect, control);
  load_elimination.Reduce(store1);

  // Invalidate caches of object.
  Node* store2 = effect = graph()->NewNode(simplified()->StoreField(access2),
                                         object, value, effect, control);
  load_elimination.Reduce(store2);

  Node* store3 = graph()->NewNode(simplified()->StoreField(access1),
                                          object, value, effect, control);

  Reduction r = load_elimination.Reduce(store3);

  // store3 shall not be replaced, since caches were invalidated.
  EXPECT_EQ(store3, r.replacement());
}

TEST_F(LoadEliminationTest, StoreFieldAndStoreElementAndLoadField) {
  Node* object = Parameter(Type::Any(), 0);
  Node* value = Parameter(Type::Any(), 1);
  Node* index = Parameter(Type::UnsignedSmall(), 2);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess access = {kTaggedBase,      kTaggedSize, MaybeHandle<Name>(),
                        OptionalMapRef(), Type::Any(), MachineType::AnyTagged(),
                        kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* store1 = effect = graph()->NewNode(simplified()->StoreField(access),
                                           object, value, effect, control);
  load_elimination.Reduce(store1);

  Node* store2 = effect = graph()->NewNode(
      simplified()->StoreElement(AccessBuilder::ForFixedArrayElement()), object,
      index, object, effect, control);
  load_elimination.Reduce(store2);

  Node* load = effect = graph()->NewNode(simplified()->LoadField(access),
                                         object, effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load, value, store2, _));
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(value, r.replacement());
}

TEST_F(LoadEliminationTest, LoadElementOnTrueBranchOfDiamond) {
  Node* object = Parameter(Type::Any(), 0);
  Node* index = Parameter(Type::UnsignedSmall(), 1);
  Node* check = Parameter(Type::Boolean(), 2);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  ElementAccess const access = {kTaggedBase, kTaggedSize, Type::Any(),
                                MachineType::AnyTagged(), kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = graph()->NewNode(simplified()->LoadElement(access), object,
                                 index, effect, if_true);
  load_elimination.Reduce(etrue);

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadElement(access), object,
                                index, effect, control);
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load, r.replacement());
}

TEST_F(LoadEliminationTest, LoadElementOnFalseBranchOfDiamond) {
  Node* object = Parameter(Type::Any(), 0);
  Node* index = Parameter(Type::UnsignedSmall(), 1);
  Node* check = Parameter(Type::Boolean(), 2);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  ElementAccess const access = {kTaggedBase, kTaggedSize, Type::Any(),
                                MachineType::AnyTagged(), kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = graph()->NewNode(simplified()->LoadElement(access), object,
                                  index, effect, if_false);
  load_elimination.Reduce(efalse);

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadElement(access), object,
                                index, effect, control);
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load, r.replacement());
}

TEST_F(LoadEliminationTest, LoadFieldOnFalseBranchOfDiamond) {
  Node* object = Parameter(Type::Any(), 0);
  Node* check = Parameter(Type::Boolean(), 1);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess const access = {kTaggedBase,         kTaggedSize,
                              MaybeHandle<Name>(), OptionalMapRef(),
                              Type::Any(),         MachineType::AnyTagged(),
                              kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = graph()->NewNode(simplified()->LoadField(access), object,
                                  effect, if_false);
  load_elimination.Reduce(efalse);

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadField(access), object, effect,
                                control);
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load, r.replacement());
}

TEST_F(LoadEliminationTest, LoadFieldOnTrueBranchOfDiamond) {
  Node* object = Parameter(Type::Any(), 0);
  Node* check = Parameter(Type::Boolean(), 1);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess const access = {kTaggedBase,         kTaggedSize,
                              MaybeHandle<Name>(), OptionalMapRef(),
                              Type::Any(),         MachineType::AnyTagged(),
                              kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = graph()->NewNode(simplified()->LoadField(access), object,
                                 effect, if_true);
  load_elimination.Reduce(etrue);

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadField(access), object, effect,
                                control);
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load, r.replacement());
}

TEST_F(LoadEliminationTest, LoadFieldWithTypeMismatch) {
  Node* object = Parameter(Type::Any(), 0);
  Node* value = Parameter(Type::Signed32(), 1);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess const access = {kTaggedBase,         kTaggedSize,
                              MaybeHandle<Name>(), OptionalMapRef(),
                              Type::Unsigned31(),  MachineType::AnyTagged(),
                              kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  effect = graph()->NewNode(simplified()->StoreField(access), object, value,
                            effect, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadField(access), object, effect,
                                control);
  EXPECT_CALL(editor, ReplaceWithValue(load, IsTypeGuard(value, _), _, _));
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_THAT(r.replacement(), IsTypeGuard(value, _));
}

TEST_F(LoadEliminationTest, LoadElementWithTypeMismatch) {
  Node* object = Parameter(Type::Any(), 0);
  Node* index = Parameter(Type::UnsignedSmall(), 1);
  Node* value = Parameter(Type::Signed32(), 2);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  ElementAccess const access = {kTaggedBase, kTaggedSize, Type::Unsigned31(),
                                MachineType::AnyTagged(), kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(graph()->start());

  effect = graph()->NewNode(simplified()->StoreElement(access), object, index,
                            value, effect, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadElement(access), object,
                                index, effect, control);
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(load, r.replacement());
}

TEST_F(LoadEliminationTest, AliasAnalysisForFinishRegion) {
  Node* value0 = Parameter(Type::Signed32(), 0);
  Node* value1 = Parameter(Type::Signed32(), 1);
  Node* effect = graph()->start();
  Node* control = graph()->start();
  FieldAccess const access = {kTaggedBase,         kTaggedSize,
                              MaybeHandle<Name>(), OptionalMapRef(),
                              Type::Signed32(),    MachineType::AnyTagged(),
                              kNoWriteBarrier};

  StrictMock<MockAdvancedReducerEditor> editor;
  LoadElimination load_elimination(&editor, broker(), jsgraph(), zone());

  load_elimination.Reduce(effect);

  effect = graph()->NewNode(
      common()->BeginRegion(RegionObservability::kNotObservable), effect);
  load_elimination.Reduce(effect);

  Node* object0 = effect = graph()->NewNode(
      simplified()->Allocate(Type::Any(), AllocationType::kYoung),
      jsgraph()->ConstantNoHole(16), effect, control);
  load_elimination.Reduce(effect);

  Node* region0 = effect =
      graph()->NewNode(common()->FinishRegion(), object0, effect);
  load_elimination.Reduce(effect);

  effect = graph()->NewNode(
      common()->BeginRegion(RegionObservability::kNotObservable), effect);
  load_elimination.Reduce(effect);

  Node* object1 = effect = graph()->NewNode(
      simplified()->Allocate(Type::Any(), AllocationType::kYoung),
      jsgraph()->ConstantNoHole(16), effect, control);
  load_elimination.Reduce(effect);

  Node* region1 = effect =
      graph()->NewNode(common()->FinishRegion(), object1, effect);
  load_elimination.Reduce(effect);

  effect = graph()->NewNode(simplified()->StoreField(access), region0, value0,
                            effect, control);
  load_elimination.Reduce(effect);

  effect = graph()->NewNode(simplified()->StoreField(access), region1, value1,
                            effect, control);
  load_elimination.Reduce(effect);

  Node* load = graph()->NewNode(simplified()->LoadField(access), region0,
                                effect, control);
  EXPECT_CALL(editor, ReplaceWithValue(load, value0, effect, _));
  Reduction r = load_elimination.Reduce(load);
  ASSERT_TRUE(r.Changed());
  EXPECT_EQ(value0, r.replacement());
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```