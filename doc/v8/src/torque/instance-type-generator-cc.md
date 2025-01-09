Response:
Let's break down the thought process for analyzing the `instance-type-generator.cc` code.

1. **Understand the Goal:** The file name itself, "instance-type-generator.cc," is a huge clue. The primary function is likely to generate or assign instance types for classes defined in Torque. The comments at the beginning of the file reinforce this.

2. **Identify Key Data Structures:** Look for the core structures that hold and manipulate the data. `InstanceTypeTree` immediately stands out. This structure appears to represent the class hierarchy and store information related to instance type assignments. Pay attention to its members: `type`, `children`, `start`, `end`, `value`, `num_values`, and `num_own_values`. Each member likely plays a crucial role in the instance type assignment process.

3. **Trace the Main Functions:**  Identify the high-level functions and their purpose.
    * `BuildInstanceTypeTree()`: This function clearly constructs the class hierarchy tree. It iterates through declarables, finds class types, and links them based on inheritance.
    * `PropagateInstanceTypeConstraints()`: This function sounds like it's pushing information *down* the tree, likely applying constraints from parent classes to their children. The logic involves updating `start`, `end`, and `num_values` based on children's properties and explicit constraints.
    * `SolveInstanceTypeConstraints()`: This is the core logic for *assigning* the actual instance type values. The comments within the function about sorting children and handling constrained/unconstrained types suggest a complex assignment algorithm.
    * `AssignInstanceTypes()`: This acts as the orchestrator, calling the build, propagate, and solve functions in sequence.
    * `PrintInstanceTypes()`: This function is responsible for generating output, likely the C++ header file. The different output streams (definitions, values, etc.) indicate that it generates various macro definitions related to instance types.
    * `GenerateInstanceTypes()`: This is the entry point, setting up the output stream, calling `AssignInstanceTypes`, and then `PrintInstanceTypes`.

4. **Analyze the Algorithms:**  For the more complex functions like `SolveInstanceTypeConstraints`, carefully examine the steps.
    * **Grouping Children:** The division of children into `lowest_child`, `highest_child`, `constrained_children_by_start`, and `unconstrained_children_by_size` suggests a sophisticated assignment strategy based on explicit ordering, fixed values, and flexible ranges.
    * **Greedy Approach:** The comment about the "simple greedy algorithm" in the unconstrained child processing is important. It tells us the algorithm prioritizes placing larger unconstrained ranges first, even if it's not perfectly optimal.
    * **Handling Constraints:** Pay attention to how `start_value` is managed and how errors are reported if constraints cannot be satisfied.

5. **Infer Relationships to JavaScript:**  Think about how instance types relate to JavaScript. JavaScript objects have internal representations, and V8 uses instance types to categorize them. The generated macros (like `FIRST_OBJECT_TYPE`, `LAST_OBJECT_TYPE`, `OBJECT_TYPE`) are used within the V8 codebase to perform type checks and optimize object access.

6. **Consider Potential User Errors:**  Think about how developers working with Torque might misuse the features this code generates. For instance, incorrectly specifying `LowestInstanceTypeWithinParent` or `HighestInstanceTypeWithinParent` for multiple subclasses could lead to errors this code detects. Manually assigning instance type values that conflict with the automated assignment is another potential issue.

7. **Structure the Explanation:** Organize the findings into logical sections:
    * **Core Functionality:** Start with the main purpose of the file.
    * **Torque Relationship:** Explain its role in the Torque compilation process.
    * **JavaScript Connection:**  Illustrate with JavaScript examples how instance types are conceptually related (even though developers don't directly interact with these specific values).
    * **Code Logic/Reasoning:** Explain the key functions and the algorithms they employ, including assumptions and inputs/outputs.
    * **Common Errors:** Provide concrete examples of programming mistakes related to the concepts handled by this code.

8. **Review and Refine:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation and make sure the examples are relevant and easy to understand. For example, initially, I might have just said "it assigns instance types."  Refining it to explain *how* it does it (by building a tree, propagating constraints, and then solving) is much more informative. Similarly, just saying "it generates a header file" isn't enough; explaining the *purpose* of the macros in that header file is essential.
`v8/src/torque/instance-type-generator.cc` 的主要功能是为在 Torque 中定义的类生成唯一的 **实例类型**（Instance Types）。

如果 `v8/src/torque/instance-type-generator.cc` 以 `.tq` 结尾，那将是一个 Torque 源代码文件，用于定义数据结构和操作。然而，这个文件是以 `.cc` 结尾，表明它是用 C++ 编写的，并且是 Torque 编译过程的一部分，负责生成 C++ 代码。

**功能详解:**

1. **构建实例类型树 (BuildInstanceTypeTree):**
   - 遍历所有在 Torque 中声明的类类型（通过 `GlobalContext::AllDeclarables()`）。
   - 为每个非抽象类创建一个 `InstanceTypeTree` 节点。
   - 将这些节点组织成一个树状结构，反映类的继承关系。根节点是没有父类的类。

2. **传播实例类型约束 (PropagateInstanceTypeConstraints):**
   - 从叶子节点（子类）向根节点（父类）传播实例类型约束。
   - 这些约束可能包括：
     - 子类实例类型范围的起始和结束值。
     - 特定类是否需要分配一个单独的实例类型值。
     - 通过 `GetInstanceTypeConstraints()` 获取的显式约束（例如，固定的实例类型值或标志位数）。

3. **解决实例类型约束 (SolveInstanceTypeConstraints):**
   - 为每个类分配具体的实例类型值或范围。
   - 考虑以下因素：
     - 显式指定的实例类型值。
     - 是否要求作为父类实例类型范围的第一个或最后一个。
     - 子类的实例类型范围。
     - 尽量紧凑地分配实例类型值，避免浪费。
   - 该函数使用一种贪婪算法来分配未约束的子类的实例类型。

4. **生成 C++ 头文件 (GenerateInstanceTypes):**
   - 将分配的实例类型信息写入一个 C++ 头文件 `instance-types.h`。
   - 生成一系列 C 预处理器宏，例如：
     - `TORQUE_ASSIGNED_INSTANCE_TYPES(V)`: 定义了实例类型名称和对应的值，包括 `FIRST_*` 和 `LAST_*` 用于表示范围。
     - `TORQUE_ASSIGNED_INSTANCE_TYPE_LIST(V)`: 列出所有分配的实例类型名称。
     - `TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(V)` 和其他类似的宏：用于生成类型检查相关的代码，区分了完全定义的类和仅声明的类，以及单实例类型和多实例类型的情况。
     - `TORQUE_DEFINED_CLASS_LIST(V)`: 列出所有在 Torque 中定义的类。
     - `TORQUE_DEFINED_INSTANCE_TYPE_LIST(V)`: 列出与 Torque 定义的类关联的实例类型。
     - `TORQUE_DEFINED_MAP_CSA_LIST_GENERATOR(V, _)` 和 `TORQUE_DEFINED_MAP_ROOT_LIST(V)`: 用于生成与 Map 对象相关的 CSA（CodeStubAssembler）代码。

**与 JavaScript 的关系:**

实例类型是 V8 内部用来区分不同种类 JavaScript 对象的机制。 虽然 JavaScript 开发者通常不直接操作实例类型的值，但它们在 V8 的运行时系统中至关重要。

例如，考虑以下 JavaScript 代码：

```javascript
const obj = {};
const arr = [];
const func = () => {};
```

在 V8 内部，`obj`、`arr` 和 `func` 会被赋予不同的实例类型，例如 `JS_OBJECT_TYPE`, `JS_ARRAY_TYPE`, 和 `JS_FUNCTION_TYPE`。 `instance-type-generator.cc` 生成的代码会定义这些类型及其相关的常量。

生成的宏可以用于 V8 的 C++ 代码中进行类型检查和优化，例如：

```c++
// 假设生成的头文件中定义了 JS_ARRAY_TYPE
if (object->IsJSArray()) {
  // 执行数组相关的操作
}
```

**代码逻辑推理 (假设输入与输出):**

假设在 Torque 中定义了以下类继承关系：

```torque
class A extends Object {};
class B extends A {};
class C extends A {};
```

`instance-type-generator.cc` 的逻辑会执行以下步骤：

1. **构建树:** 构建一个包含 A、B 和 C 的 `InstanceTypeTree`，其中 A 是根节点，B 和 C 是 A 的子节点。

2. **传播约束:**  假设没有显式的约束，传播过程主要是确定子类需要独立的实例类型。

3. **解决约束:**  可能会分配如下的实例类型值（实际分配可能不同）：
   - A:  `FIRST_A_TYPE` = 10, `LAST_A_TYPE` = 12
   - B:  `B_TYPE` = 10
   - C:  `C_TYPE` = 11

4. **生成头文件:**  `instance-types.h` 中会包含类似以下的宏定义：

```c++
#define TORQUE_ASSIGNED_INSTANCE_TYPES(V) \
  V(FIRST_A_TYPE, 10) \
    V(B_TYPE, 10) /* ... */ \
    V(C_TYPE, 11) /* ... */ \
  V(LAST_A_TYPE, 12) \

#define TORQUE_ASSIGNED_INSTANCE_TYPE_LIST(V) \
  V(B_TYPE) /* ... */ \
  V(C_TYPE) /* ... */ \

#define TORQUE_INSTANCE_CHECKERS_RANGE_FULLY_DEFINED(V) \
  V(A, FIRST_A_TYPE, LAST_A_TYPE) \
```

**用户常见的编程错误 (与 Torque 相关):**

虽然用户不直接编写或修改 `instance-type-generator.cc`，但在编写 Torque 代码时，一些错误可能会影响到实例类型的生成：

1. **实例类型约束冲突:** 如果在 Torque 中为某个类显式指定了实例类型值，但该值与其他类的分配冲突，`instance-type-generator.cc` 会报错。

   **示例 (假设在 Torque 中):**

   ```torque
   // 错误：假设 Object 已经分配了实例类型 0
   [@FixedInstanceType(0)]
   class MyObject extends Object {};
   ```

   `instance-type-generator.cc` 在尝试为 `MyObject` 分配实例类型时，如果 0 已经被占用，将会报错。

2. **不一致的 `LowestInstanceTypeWithinParent` 和 `HighestInstanceTypeWithinParent` 注解:** 如果多个子类都标记为父类的最低或最高实例类型，`instance-type-generator.cc` 会报错，因为它无法确定正确的顺序。

   **示例 (假设在 Torque 中):**

   ```torque
   [@LowestInstanceTypeWithinParent]
   class Subclass1 extends Parent {};

   [@LowestInstanceTypeWithinParent]
   class Subclass2 extends Parent {};
   ```

   `instance-type-generator.cc` 会检测到 `Subclass1` 和 `Subclass2` 都试图成为 `Parent` 的最低实例类型，从而报错。

3. **抽象类指定实例类型值:** 抽象类本身不应该有实例，因此为其指定具体的实例类型值通常是错误的。`instance-type-generator.cc` 会检查这种情况并报错。

   **示例 (假设在 Torque 中):**

   ```torque
   [@FixedInstanceType(10)] // 错误：抽象类不应有固定的实例类型
   abstract class AbstractClass extends Object {};
   ```

   `instance-type-generator.cc` 会检测到为抽象类 `AbstractClass` 尝试分配固定的实例类型值，并可能报错。

总而言之，`v8/src/torque/instance-type-generator.cc` 是 Torque 编译过程中的一个关键组件，负责生成 V8 运行时所需的实例类型信息，这些信息对于 V8 的对象模型和类型系统至关重要。虽然开发者不直接修改这个文件，但理解其功能有助于理解 Torque 代码如何影响 V8 的内部表示。

Prompt: 
```
这是目录为v8/src/torque/instance-type-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/instance-type-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/torque/implementation-visitor.h"

namespace v8::internal::torque {

namespace {

// Contains all necessary state for a single class type during the process of
// assigning instance types, and provides a convenient way to access the list of
// types that inherit from this one.
struct InstanceTypeTree {
  explicit InstanceTypeTree(const ClassType* type)
      : type(type),
        start(INT_MAX),
        end(INT_MIN),
        value(-1),
        num_values(0),
        num_own_values(0) {}
  const ClassType* type;
  std::vector<std::unique_ptr<InstanceTypeTree>> children;
  int start;  // Start of range for this and subclasses, or INT_MAX.
  int end;    // End of range for this and subclasses, or INT_MIN.
  int value;  // Assigned value for this class itself, or -1 when unassigned.
  int num_values;      // Number of values assigned for this and subclasses.
  int num_own_values;  // How many values this needs (not including subclasses).
};

// Assembles all class types into a tree, but doesn't yet attempt to assign
// instance types for them.
std::unique_ptr<InstanceTypeTree> BuildInstanceTypeTree() {
  // First, build InstanceTypeTree instances for every class but don't try to
  // attach them to their subclasses yet.
  std::unordered_map<const ClassType*, InstanceTypeTree*> map_by_type;
  std::vector<std::unique_ptr<InstanceTypeTree>> unparented_types;
  for (auto& p : GlobalContext::AllDeclarables()) {
    if (const TypeAlias* alias = TypeAlias::DynamicCast(p.get())) {
      const Type* type = alias->type();
      const ClassType* class_type = ClassType::DynamicCast(type);
      if (class_type == nullptr) {
        continue;
      }
      auto& map_slot = map_by_type[class_type];
      if (map_slot != nullptr) {
        continue;  // We already encountered this type.
      }
      std::unique_ptr<InstanceTypeTree> type_tree =
          std::make_unique<InstanceTypeTree>(class_type);
      map_slot = type_tree.get();
      unparented_types.push_back(std::move(type_tree));
    }
  }

  // Second, assemble them all into a tree following the inheritance hierarchy.
  std::unique_ptr<InstanceTypeTree> root;
  for (auto& type_tree : unparented_types) {
    const ClassType* parent = type_tree->type->GetSuperClass();
    if (parent == nullptr) {
      if (root != nullptr)
        Error("Expected only one root class type. Found: ", root->type->name(),
              " and ", type_tree->type->name())
            .Position(type_tree->type->GetPosition());
      root = std::move(type_tree);
    } else {
      map_by_type[parent]->children.push_back(std::move(type_tree));
    }
  }
  return root;
}

// Propagates constraints about instance types from children to their parents.
void PropagateInstanceTypeConstraints(InstanceTypeTree* root) {
  for (auto& child : root->children) {
    PropagateInstanceTypeConstraints(child.get());
    if (child->start < root->start) root->start = child->start;
    if (child->end > root->end) root->end = child->end;
    root->num_values += child->num_values;
  }
  const InstanceTypeConstraints& constraints =
      root->type->GetInstanceTypeConstraints();
  if (!root->type->IsAbstract() && !root->type->HasSameInstanceTypeAsParent()) {
    root->num_own_values = 1;
  }
  root->num_values += root->num_own_values;
  if (constraints.num_flags_bits != -1) {
    // Children won't get any types assigned; must be done manually in C++.
    root->children.clear();
    root->num_values = 1 << constraints.num_flags_bits;
    root->num_own_values = root->num_values;
    root->start = 0;
    root->end = root->num_values - 1;
  }
  if (constraints.value != -1) {
    if (root->num_own_values != 1) {
      Error("Instance type value requested for abstract class ",
            root->type->name())
          .Position(root->type->GetPosition());
    }
    root->value = constraints.value;
    if (constraints.value < root->start) root->start = constraints.value;
    if (constraints.value > root->end) root->end = constraints.value;
  }
}

// Assigns values for the type itself, not including any children. Returns the
// next available value.
int SelectOwnValues(InstanceTypeTree* root, int start_value) {
  if (root->value == -1) {
    root->value = start_value;
  } else if (root->value < start_value) {
    Error("Failed to assign instance type ", root->value, " to ",
          root->type->name())
        .Position(root->type->GetPosition());
  }
  return root->value + root->num_own_values;
}

// Sorting function for types that don't have specific values they must include.
// Prioritizes bigger type ranges (those with more subtypes) first, and
// then sorts alphabetically within each size category.
struct CompareUnconstrainedTypes {
  constexpr bool operator()(const InstanceTypeTree* a,
                            const InstanceTypeTree* b) const {
    return (a->num_values > b->num_values)
               ? true
               : (a->num_values < b->num_values)
                     ? false
                     : std::less<std::string>()(a->type->name(),
                                                b->type->name());
  }
};

// Assigns concrete values for every instance type range, and sorts the children
// at each layer of the tree into increasing order. Appends the newly-assigned
// tree to the destination vector. Returns the first unassigned value after
// those that have been used.
int SolveInstanceTypeConstraints(
    std::unique_ptr<InstanceTypeTree> root, int start_value,
    std::vector<std::unique_ptr<InstanceTypeTree>>* destination) {
  if (root->start < start_value) {
    Error("Failed to assign instance type ", root->start, " to ",
          root->type->name())
        .Position(root->type->GetPosition());
  }

  // First, separate the children into four groups:
  // - The one child that must go first, if it exists;
  // - Children with specific value requirements ("constrained");
  // - Children without specific value requirements ("unconstrained");
  // - The one child that must go last, if it exists.
  std::unique_ptr<InstanceTypeTree> lowest_child;
  std::unique_ptr<InstanceTypeTree> highest_child;
  std::multimap<int, std::unique_ptr<InstanceTypeTree>>
      constrained_children_by_start;
  // Using std::map because you can't std::move out of a std::set until C++17.
  std::map<InstanceTypeTree*, std::unique_ptr<InstanceTypeTree>,
           CompareUnconstrainedTypes>
      unconstrained_children_by_size;
  for (auto& child : root->children) {
    if (child->type->IsHighestInstanceTypeWithinParent()) {
      if (highest_child) {
        Error("Two classes requested to be the highest instance type: ",
              highest_child->type->name(), " and ", child->type->name(),
              " within range for parent class ", root->type->name())
            .Position(child->type->GetPosition());
      }
      if (child->type->IsLowestInstanceTypeWithinParent()) {
        Error(
            "Class requested to be both highest and lowest instance type "
            "within its parent range: ",
            child->type->name())
            .Position(child->type->GetPosition());
      }
      highest_child = std::move(child);
    } else if (child->type->IsLowestInstanceTypeWithinParent()) {
      if (lowest_child) {
        Error("Two classes requested to be the lowest instance type: ",
              lowest_child->type->name(), " and ", child->type->name(),
              " within range for parent class ", root->type->name())
            .Position(child->type->GetPosition());
      }
      lowest_child = std::move(child);
    } else if (child->start > child->end) {
      unconstrained_children_by_size.insert(
          std::make_pair(child.get(), std::move(child)));
    } else {
      constrained_children_by_start.insert(
          std::make_pair(child->start, std::move(child)));
    }
  }
  root->children.clear();

  bool own_type_pending = root->num_own_values > 0;

  // Second, iterate and place the children in ascending order.
  if (lowest_child != nullptr) {
    start_value = SolveInstanceTypeConstraints(std::move(lowest_child),
                                               start_value, &root->children);
  }
  for (auto& constrained_child_pair : constrained_children_by_start) {
    // Select the next constrained child type in ascending order.
    std::unique_ptr<InstanceTypeTree> constrained_child =
        std::move(constrained_child_pair.second);

    // Try to place the root type before the constrained child type if it fits.
    if (own_type_pending) {
      if ((root->value != -1 && root->value < constrained_child->start) ||
          (root->value == -1 &&
           start_value + root->num_own_values <= constrained_child->start)) {
        start_value = SelectOwnValues(root.get(), start_value);
        own_type_pending = false;
      }
    }

    // Try to find any unconstrained children that fit before the constrained
    // one. This simple greedy algorithm just puts the biggest unconstrained
    // children in first, which might not fill the space as efficiently as
    // possible but is good enough for our needs.
    for (auto it = unconstrained_children_by_size.begin();
         it != unconstrained_children_by_size.end();) {
      if (it->second->num_values + start_value <= constrained_child->start) {
        start_value = SolveInstanceTypeConstraints(
            std::move(it->second), start_value, &root->children);
        it = unconstrained_children_by_size.erase(it);
      } else {
        ++it;
      }
    }

    // Place the constrained child type.
    start_value = SolveInstanceTypeConstraints(std::move(constrained_child),
                                               start_value, &root->children);
  }
  if (own_type_pending) {
    start_value = SelectOwnValues(root.get(), start_value);
    own_type_pending = false;
  }
  for (auto& child_pair : unconstrained_children_by_size) {
    start_value = SolveInstanceTypeConstraints(std::move(child_pair.second),
                                               start_value, &root->children);
  }
  if (highest_child != nullptr) {
    start_value = SolveInstanceTypeConstraints(std::move(highest_child),
                                               start_value, &root->children);
  }

  // Finally, set the range for this class to include all placed subclasses.
  root->end = start_value - 1;
  root->start =
      root->children.empty() ? start_value : root->children.front()->start;
  if (root->value != -1 && root->value < root->start) {
    root->start = root->value;
  }
  root->num_values = root->end - root->start + 1;
  root->type->InitializeInstanceTypes(
      root->value == -1 ? std::optional<int>{} : root->value,
      std::make_pair(root->start, root->end));

  if (root->num_values > 0) {
    destination->push_back(std::move(root));
  }
  return start_value;
}

std::unique_ptr<InstanceTypeTree> SolveInstanceTypeConstraints(
    std::unique_ptr<InstanceTypeTree> root) {
  std::vector<std::unique_ptr<InstanceTypeTree>> destination;
  SolveInstanceTypeConstraints(std::move(root), 0, &destination);
  return destination.empty() ? nullptr : std::move(destination.front());
}

std::unique_ptr<InstanceTypeTree> AssignInstanceTypes() {
  std::unique_ptr<InstanceTypeTree> root = BuildInstanceTypeTree();
  if (root != nullptr) {
    PropagateInstanceTypeConstraints(root.get());
    root = SolveInstanceTypeConstraints(std::move(root));
  }
  return root;
}

// Prints items in macro lists for the given type and its descendants.
// - definitions: This list is pairs of instance type name and assigned value,
//   such as V(ODDBALL_TYPE, 67). It includes FIRST_* and LAST_* items for each
//   type that has more than one associated InstanceType. Items within those
//   ranges are indented for readability.
// - values: This list is just instance type names, like V(ODDBALL_TYPE). It
//   does not include any FIRST_* and LAST_* range markers.
// - fully_defined_single_instance_types: This list is pairs of class name and
//   instance type, for classes which have defined layouts and a single
//   corresponding instance type.
// - fully_defined_multiple_instance_types: This list is pairs of class name and
//   instance type, for classes which have defined layouts and subclasses.
// - only_declared_single_instance_types: This list is pairs of class name and
//   instance type, for classes which have a single corresponding instance type
//   and do not have layout definitions in Torque.
// - only_declared_multiple_instance_types: This list is pairs of class name and
//   instance type, for classes which have subclasses but also have a single
//   corresponding instance type, and do not have layout definitions in Torque.
// - fully_defined_range_instance_types: This list is triples of class name,
//   first instance type, and last instance type, for classes which have defined
//   layouts and multiple corresponding instance types.
// - only_declared_range_instance_types: This list is triples of class name,
//   first instance type, and last instance type, for classes which have
//   multiple corresponding instance types and do not have layout definitions in
//   Torque.
void PrintInstanceTypes(InstanceTypeTree* root, std::ostream& definitions,
                        std::ostream& values,
                        std::ostream& fully_defined_single_instance_types,
                        std::ostream& fully_defined_multiple_instance_types,
                        std::ostream& only_declared_single_instance_types,
                        std::ostream& only_declared_multiple_instance_types,
                        std::ostream& fully_defined_range_instance_types,
                        std::ostream& only_declared_range_instance_types,
                        const std::string& indent) {
  std::string type_name =
      CapifyStringWithUnderscores(root->type->name()) + "_TYPE";
  std::string inner_indent = indent;

  if (root->num_values > 1) {
    definitions << indent << "V(FIRST_" << type_name << ", " << root->start
                << ") \\\n";
    inner_indent += "  ";
  }
  if (root->num_own_values == 1) {
    definitions << inner_indent << "V(" << type_name << ", " << root->value
                << ") /* " << root->type->GetPosition() << " */\\\n";
    values << "  V(" << type_name << ") /* " << root->type->GetPosition()
           << " */\\\n";
    std::ostream& type_checker_list =
        root->type->HasUndefinedLayout()
            ? (root->num_values == 1 ? only_declared_single_instance_types
                                     : only_declared_multiple_instance_types)
            : (root->num_values == 1 ? fully_defined_single_instance_types
                                     : fully_defined_multiple_instance_types);
    type_checker_list << "  V(" << root->type->name() << ", " << type_name
                      << ") /* " << root->type->GetPosition() << " */ \\\n";
  }
  for (auto& child : root->children) {
    PrintInstanceTypes(child.get(), definitions, values,
                       fully_defined_single_instance_types,
                       fully_defined_multiple_instance_types,
                       only_declared_single_instance_types,
                       only_declared_multiple_instance_types,
                       fully_defined_range_instance_types,
                       only_declared_range_instance_types, inner_indent);
  }
  if (root->num_values > 1) {
    // We can't emit LAST_STRING_TYPE because it's not a valid flags
    // combination. So if the class type has multiple own values, which only
    // happens when using ANNOTATION_RESERVE_BITS_IN_INSTANCE_TYPE, then omit
    // the end marker.
    if (root->num_own_values <= 1) {
      definitions << indent << "V(LAST_" << type_name << ", " << root->end
                  << ") \\\n";
    }

    // Only output the instance type range for things other than the root type.
    if (root->type->GetSuperClass() != nullptr) {
      std::ostream& range_instance_types =
          root->type->HasUndefinedLayout() ? only_declared_range_instance_types
                                           : fully_defined_range_instance_types;
      range_instance_types << "  V(" << root->type->name() << ", FIRST_"
                           << type_name << ", LAST_" << type_name << ") \\\n";
    }
  }
}

}  // namespace

void ImplementationVisitor::GenerateInstanceTypes(
    const std::string& output_directory) {
  std::stringstream header;
  std::string file_name = "instance-types.h";
  {
    IncludeGuardScope guard(header, file_name);

    header << "// Instance types for all classes except for those that use "
              "InstanceType as flags.\n";
    header << "#define TORQUE_ASSIGNED_INSTANCE_TYPES(V) \\\n";
    std::unique_ptr<InstanceTypeTree> instance_types = AssignInstanceTypes();
    std::stringstream values_list;
    std::stringstream fully_defined_single_instance_types;
    std::stringstream fully_defined_multiple_instance_types;
    std::stringstream only_declared_single_instance_types;
    std::stringstream only_declared_multiple_instance_types;
    std::stringstream fully_defined_range_instance_types;
    std::stringstream only_declared_range_instance_types;
    if (instance_types != nullptr) {
      PrintInstanceTypes(instance_types.get(), header, values_list,
                         fully_defined_single_instance_types,
                         fully_defined_multiple_instance_types,
                         only_declared_single_instance_types,
                         only_declared_multiple_instance_types,
                         fully_defined_range_instance_types,
                         only_declared_range_instance_types, "  ");
    }
    header << "\n";

    header << "// Instance types for all classes except for those that use\n";
    header << "// InstanceType as flags.\n";
    header << "#define TORQUE_ASSIGNED_INSTANCE_TYPE_LIST(V) \\\n";
    header << values_list.str();
    header << "\n";

    header << "// Pairs of (ClassName, INSTANCE_TYPE) for classes that have\n";
    header << "// full Torque definitions.\n";
    header << "#define TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(V) \\\n";
    header << fully_defined_single_instance_types.str();
    header << "\n";

    header << "// Pairs of (ClassName, INSTANCE_TYPE) for classes that have\n";
    header << "// full Torque definitions and subclasses.\n";
    header << "#define TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(V) \\\n";
    header << fully_defined_multiple_instance_types.str();
    header << "\n";

    header << "// Pairs of (ClassName, INSTANCE_TYPE) for classes that are\n";
    header << "// declared but not defined in Torque. These classes may\n";
    header << "// correspond with actual C++ classes, but they are not\n";
    header << "// guaranteed to.\n";
    header << "#define TORQUE_INSTANCE_CHECKERS_SINGLE_ONLY_DECLARED(V) \\\n";
    header << only_declared_single_instance_types.str();
    header << "\n";

    header << "// Pairs of (ClassName, INSTANCE_TYPE) for classes that are\n";
    header << "// declared but not defined in Torque, and have subclasses.\n";
    header << "// These classes may correspond with actual C++ classes, but\n";
    header << "// they are not guaranteed to.\n";
    header << "#define TORQUE_INSTANCE_CHECKERS_MULTIPLE_ONLY_DECLARED(V) \\\n";
    header << only_declared_multiple_instance_types.str();
    header << "\n";

    header << "// Triples of (ClassName, FIRST_TYPE, LAST_TYPE) for classes\n";
    header << "// that have full Torque definitions.\n";
    header << "#define TORQUE_INSTANCE_CHECKERS_RANGE_FULLY_DEFINED(V) \\\n";
    header << fully_defined_range_instance_types.str();
    header << "\n";

    header << "// Triples of (ClassName, FIRST_TYPE, LAST_TYPE) for classes\n";
    header << "// that are declared but not defined in Torque. These classes\n";
    header << "// may correspond with actual C++ classes, but they are not\n";
    header << "// guaranteed to.\n";
    header << "#define TORQUE_INSTANCE_CHECKERS_RANGE_ONLY_DECLARED(V) \\\n";
    header << only_declared_range_instance_types.str();
    header << "\n";

    std::stringstream torque_defined_class_list;
    std::stringstream torque_defined_varsize_instance_type_list;
    std::stringstream torque_defined_fixed_instance_type_list;
    std::stringstream torque_defined_map_csa_list;
    std::stringstream torque_defined_map_root_list;

    for (const ClassType* type : TypeOracle::GetClasses()) {
      std::string upper_case_name = type->name();
      std::string lower_case_name = SnakeifyString(type->name());
      std::string instance_type_name =
          CapifyStringWithUnderscores(type->name()) + "_TYPE";

      if (!type->IsExtern()) {
        torque_defined_class_list << "  V(" << upper_case_name << ") \\\n";
      }

      if (type->ShouldGenerateUniqueMap()) {
        torque_defined_map_csa_list << "  V(_, " << upper_case_name << "Map, "
                                    << lower_case_name << "_map, "
                                    << upper_case_name << ") \\\n";
        torque_defined_map_root_list << "  V(Map, " << lower_case_name
                                     << "_map, " << upper_case_name
                                     << "Map) \\\n";
        std::stringstream& list =
            type->HasStaticSize() ? torque_defined_fixed_instance_type_list
                                  : torque_defined_varsize_instance_type_list;
        list << "  V(" << instance_type_name << ", " << upper_case_name << ", "
             << lower_case_name << ") \\\n";
      }
    }

    header << "// Fully Torque-defined classes (both internal and exported).\n";
    header << "#define TORQUE_DEFINED_CLASS_LIST(V) \\\n";
    header << torque_defined_class_list.str();
    header << "\n";
    header << "#define TORQUE_DEFINED_VARSIZE_INSTANCE_TYPE_LIST(V) \\\n";
    header << torque_defined_varsize_instance_type_list.str();
    header << "\n";
    header << "#define TORQUE_DEFINED_FIXED_INSTANCE_TYPE_LIST(V) \\\n";
    header << torque_defined_fixed_instance_type_list.str();
    header << "\n";
    header << "#define TORQUE_DEFINED_INSTANCE_TYPE_LIST(V) \\\n";
    header << "  TORQUE_DEFINED_VARSIZE_INSTANCE_TYPE_LIST(V) \\\n";
    header << "  TORQUE_DEFINED_FIXED_INSTANCE_TYPE_LIST(V) \\\n";
    header << "\n";
    header << "#define TORQUE_DEFINED_MAP_CSA_LIST_GENERATOR(V, _) \\\n";
    header << torque_defined_map_csa_list.str();
    header << "\n";
    header << "#define TORQUE_DEFINED_MAP_ROOT_LIST(V) \\\n";
    header << torque_defined_map_root_list.str();
    header << "\n";
  }
  std::string output_header_path = output_directory + "/" + file_name;
  WriteFile(output_header_path, header.str());

  GlobalContext::SetInstanceTypesInitialized();
}

}  // namespace v8::internal::torque

"""

```