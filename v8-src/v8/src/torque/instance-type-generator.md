Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly read through the code, looking for familiar keywords and structures. Things that immediately jump out:

* `// Copyright 2019 the V8 project authors`: This tells us it's part of the V8 JavaScript engine.
* `#include`: Standard C++ includes, suggesting this code interacts with other parts of V8.
* `namespace v8::internal::torque`:  This clearly indicates the code is within the "Torque" component of V8. Torque is V8's built-in language for specifying runtime functions.
* `struct InstanceTypeTree`: A custom data structure, likely representing the inheritance hierarchy of objects.
* `ClassType`:  This suggests the code deals with classes, a concept shared with object-oriented programming and JavaScript.
* `BuildInstanceTypeTree`, `PropagateInstanceTypeConstraints`, `SolveInstanceTypeConstraints`, `AssignInstanceTypes`: These function names clearly indicate the code's main purpose is to assign some kind of "instance types."
* `PrintInstanceTypes`: This function is responsible for generating output, likely code.
* `ImplementationVisitor::GenerateInstanceTypes`: This seems to be the main entry point of the code.
* `#define TORQUE_ASSIGNED_INSTANCE_TYPES(...)`:  C preprocessor macros are used for code generation.
* The various `TORQUE_INSTANCE_CHECKERS_*` macros suggest the code is generating checks for object types.

**2. Focus on the Core Functionality:**

The function names and the structure of the `InstanceTypeTree` strongly suggest that this code is about assigning unique identifiers (instance types) to different kinds of JavaScript objects. The tree structure hints at handling inheritance relationships.

**3. Deeper Dive into Key Functions:**

* **`BuildInstanceTypeTree()`:**  This function iterates through "Declarables" (likely things defined in Torque), finds `ClassType` definitions, and organizes them into a tree based on inheritance. This confirms the connection to class hierarchies.
* **`PropagateInstanceTypeConstraints()`:** This function seems to gather information about instance type requirements from child classes and pass it up to their parents. Keywords like `start`, `end`, `value`, and `num_values` suggest it's calculating ranges and specific values for these identifiers.
* **`SolveInstanceTypeConstraints()`:** This is where the actual assignment of instance type values happens. It considers constraints, sorts children, and assigns numerical values.
* **`AssignInstanceTypes()`:**  This orchestrates the process: build the tree, propagate constraints, and then solve them.
* **`PrintInstanceTypes()`:** This function takes the assigned instance type information and generates C++ preprocessor macros. The different macros like `TORQUE_ASSIGNED_INSTANCE_TYPES`, `TORQUE_INSTANCE_CHECKERS_*`, and `TORQUE_DEFINED_CLASS_LIST` indicate it's generating various code structures for different purposes.

**4. Connecting to JavaScript:**

Now, the crucial step: how does this relate to JavaScript?

* **JavaScript Objects and Classes:** JavaScript has objects and classes. V8 needs a way to efficiently determine the type of a JavaScript object at runtime. This code seems to be generating a system for that.
* **Instance Types as Identifiers:** The "instance types" being assigned are likely small integer values that represent the specific kind of JavaScript object (e.g., an Array, a Date, a custom object). This allows for fast type checking using simple integer comparisons.
* **Inheritance:** JavaScript has prototype-based inheritance. The code's handling of the class hierarchy aligns with this. Instance types likely reflect the inheritance structure, allowing V8 to quickly determine if an object is an instance of a particular class or its subclass.
* **Type Checking:** The generated macros with "CHECKERS" in their names strongly suggest they are used for runtime type checking in V8's C++ code. When V8 executes JavaScript, it needs to perform type checks to ensure operations are valid.

**5. Crafting the JavaScript Example:**

To illustrate the connection, think about how V8 would use these generated instance types internally.

* **Example Scenario:**  Consider a simple JavaScript inheritance hierarchy: `Animal` -> `Dog`. Torque might define these classes.
* **Internal Representation:** V8 would assign instance types like `ANIMAL_TYPE = 10`, `DOG_TYPE = 11`.
* **Type Checking:** When V8 encounters code like `if (animal instanceof Dog)`, it internally checks if the object's instance type is equal to `DOG_TYPE` (or within a specific range if there are more subclasses).

This leads to the example provided in the initial good answer, demonstrating the conceptual link between the C++ instance type assignments and JavaScript's `instanceof` operator.

**6. Refinement and Clarification:**

The final step is to organize the findings, use clear language, and provide a concise summary of the code's function and its relation to JavaScript. Emphasize the code generation aspect and how it facilitates efficient runtime type checking within the V8 engine. Highlight the use of Torque as the language for defining these runtime aspects.
这个C++源代码文件 `instance-type-generator.cc` 的功能是为 Torque 定义的类生成**实例类型 (instance types)**。

更具体地说，它做了以下几件事：

1. **构建实例类型树 (BuildInstanceTypeTree):**
   - 遍历 Torque 中定义的所有类 (通过 `GlobalContext::AllDeclarables()` 获取)。
   - 忽略非类类型的声明。
   - 为每个类创建一个 `InstanceTypeTree` 对象，表示该类及其子类的实例类型信息。
   - 将这些 `InstanceTypeTree` 对象根据类的继承关系组织成一棵树。

2. **传播实例类型约束 (PropagateInstanceTypeConstraints):**
   - 从叶子节点（最底层的子类）开始，向上遍历实例类型树。
   - 收集子类对实例类型的约束信息，例如起始值、结束值、固定值等。
   - 将这些约束信息传递给父类。
   - 确定每个类及其子类所需的实例类型值的范围和数量。

3. **解决实例类型约束 (SolveInstanceTypeConstraints):**
   - 从根节点开始，向下遍历实例类型树。
   - 根据收集到的约束信息，为每个类分配具体的实例类型值。
   - 考虑到用户指定的固定值、起始值和结束值。
   - 确保子类的实例类型值在父类的范围内。
   - 优先分配范围较大的子类的实例类型。

4. **生成 C++ 头文件 (GenerateInstanceTypes):**
   - 将分配好的实例类型信息以 C++ 宏定义的形式输出到 `instance-types.h` 文件中。
   - 生成多种宏定义，用于不同的目的：
     - `TORQUE_ASSIGNED_INSTANCE_TYPES`: 定义了每个实例类型的名称和对应的数值。
     - `TORQUE_ASSIGNED_INSTANCE_TYPE_LIST`:  列出了所有实例类型的名称。
     - `TORQUE_INSTANCE_CHECKERS_*`:  生成用于类型检查的宏，区分了完全定义的类和仅声明的类，以及单实例类型和多实例类型的情况。
     - `TORQUE_DEFINED_CLASS_LIST`:  列出了所有在 Torque 中定义的类。
     - `TORQUE_DEFINED_INSTANCE_TYPE_LIST`:  列出了所有在 Torque 中定义的类的实例类型。
     - `TORQUE_DEFINED_MAP_CSA_LIST_GENERATOR` 和 `TORQUE_DEFINED_MAP_ROOT_LIST`:  用于生成 Map 相关的 CSA 代码。

**与 JavaScript 的关系:**

这个文件生成的实例类型信息是 V8 引擎在运行时识别 JavaScript 对象类型的基础。在 V8 内部，每个 JavaScript 对象都会关联一个实例类型值，用于快速判断对象的具体类型。

Torque 是一种 V8 特有的语言，用于定义 V8 运行时的内置函数和对象结构。`instance-type-generator.cc` 的作用就是将 Torque 中定义的类信息转化为 V8 能够理解和使用的实例类型编码。

**JavaScript 示例:**

假设在 Torque 中定义了两个类 `A` 和 `B`，并且 `B` 继承自 `A`。`instance-type-generator.cc` 可能会生成类似以下的 C++ 宏定义：

```c++
#define TORQUE_ASSIGNED_INSTANCE_TYPES(V) \
  V(FIRST_A_TYPE, ...) \
  V(A_TYPE, 10) /* ... */ \
  V(FIRST_B_TYPE, ...) \
  V(B_TYPE, 11) /* ... */ \
  V(LAST_B_TYPE, ...) \
  V(LAST_A_TYPE, ...) \
```

在 V8 的 C++ 代码中，当需要判断一个 JavaScript 对象 `obj` 是否是 `B` 的实例时，可能会使用类似以下的检查：

```c++
// 假设 obj->instance_type() 返回对象的实例类型值
if (obj->instance_type() >= FIRST_B_TYPE && obj->instance_type() <= LAST_B_TYPE) {
  // obj 是 B 的实例或其子类的实例
}

// 或者更直接地
if (obj->instance_type() == B_TYPE) {
  // obj 是 B 的实例
}
```

在 JavaScript 中，我们可以使用 `instanceof` 运算符来判断对象的类型：

```javascript
class A {}
class B extends A {}

const a = new A();
const b = new B();

console.log(a instanceof A); // true
console.log(a instanceof B); // false
console.log(b instanceof A); // true
console.log(b instanceof B); // true
```

**内部机制关联:**

V8 引擎在执行 `instanceof` 操作时，会根据对象的内部表示（其中就包括了实例类型），与构造函数的原型链进行比较。  `instance-type-generator.cc` 生成的实例类型信息，正是 V8 内部进行这种类型判断的关键数据。它将 Torque 中定义的类层次结构映射到一组数值，使得 V8 可以高效地进行类型检查。

总而言之，`instance-type-generator.cc` 是 Torque 编译过程中的一个重要组成部分，它负责生成 V8 运行时用于对象类型识别的关键信息，从而支撑 JavaScript 的类型系统和面向对象特性。

Prompt: 
```
这是目录为v8/src/torque/instance-type-generator.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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