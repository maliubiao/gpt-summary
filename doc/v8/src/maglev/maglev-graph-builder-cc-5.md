Response:
The user wants a summary of the functionalities of the provided C++ code snippet.
The code is from `v8/src/maglev/maglev-graph-builder.cc` and it's the 6th part of 18.
The code primarily deals with type checking, type manipulation, and generating Maglev graph nodes for type assertions and memory operations.

Here's a breakdown of the functionalities:

1. **Type System Integration:** The code heavily uses a `NodeType` enum to represent the type of values in the Maglev graph. It interacts with a `StaticTypeForNode` function (not shown but assumed to exist) to determine the inherent static type of a node.
2. **Type Assertion and Refinement:**  Functions like `EnsureType`, `CheckStaticType`, `CheckType`, and `CheckTypes` are used to assert and refine the known type of a `ValueNode`. They update the `NodeInfo` associated with a node to keep track of its possible types.
3. **Value Knowledge:** The code tracks known constant values for nodes using `SetKnownValue`.
4. **Type Combination and Intersection:** Functions like `CombineType` and `IntersectType` (not shown but assumed to exist) are used to manipulate `NodeType` values.
5. **Null and Undefined Checks:** The `MayBeNullOrUndefined` function checks if a node's type allows null or undefined values.
6. **Smi (Small Integer) Handling:** Functions like `BuildSmiUntag` and `BuildCheckSmi` are specific to handling Smi values, including untagging them and ensuring a value is a Smi.
7. **Number Conversions:** The `BuildNumberOrOddballToFloat64` function handles conversions from numbers or oddball values (like booleans) to floating-point numbers.
8. **Heap Object Checks:** Functions like `BuildCheckHeapObject`, `BuildCheckString`, `BuildCheckNumber`, `BuildCheckSymbol`, and `BuildCheckJSReceiver` generate nodes to verify the type of heap objects.
9. **Map Checks:** The code includes complex logic for checking the map (object layout) of an object using `BuildCheckMaps` and related helper classes like `KnownMapsMerger`. This involves intersecting known possible maps with the required maps and emitting appropriate check nodes.
10. **Element Kind Transitions:**  `BuildTransitionElementsKindOrCheckMap` and `BuildTransitionElementsKindAndCompareMaps` handle transitions in the elements kind of arrays.
11. **Map Comparisons:** `BuildCompareMaps` generates code to compare the map of an object against a set of expected maps.
12. **Write Barrier Optimization:** The `CanElideWriteBarrier` function determines if a write barrier can be skipped during memory stores based on the types and allocation context of the involved values.
13. **Memory Stores:**  Functions like `BuildStoreTaggedField`, `BuildStoreTaggedFieldNoWriteBarrier`, and `BuildStoreTrustedPointerField` generate nodes for storing values into object fields, potentially with write barriers. `BuildInitializeStore` is used for stores during object initialization.
14. **Memory Loads:** `BuildLoadFixedArrayElement` generates nodes for loading elements from a fixed array.
15. **Object Change Tracking (Virtual Objects):** The code introduces the concept of "Virtual Objects" and functions like `CanTrackObjectChanges`, `GetObjectFromAllocation`, `GetModifiableObjectFromAllocation`, and `TryBuildStoreTaggedFieldToAllocation`. This mechanism aims to optimize object access by tracking changes to inlined allocations.

Considering these functionalities, the main purpose of this code snippet is to **provide the infrastructure for type reasoning, type safety checks, and memory access operations within the Maglev compiler**. It helps to generate efficient code by leveraging type information and optimizing memory operations like write barriers.
Based on the provided code snippet from `v8/src/maglev/maglev-graph-builder.cc`, here's a breakdown of its functionalities:

**Core Functionality:**

This code segment focuses on **managing and enforcing type information** for values within the Maglev graph being built. It provides mechanisms to:

*   **Check Static Types:** Determine if a node's inherent type (determined by its construction) matches a specific `NodeType`.
*   **Ensure Types:**  Assert that a node's type is at least a certain `NodeType`, potentially refining its known type.
*   **Track Known Values:** Associate specific constant values with nodes.
*   **Check Multiple Types:** Verify if a node's type matches any of the provided `NodeType` options.
*   **Retrieve Node Types:** Get the current known type of a node, considering both its static type and any refinements.
*   **Detect Type Differences:** Determine if two nodes or a node and a `NodeType` are guaranteed to have different types.
*   **Identify Potential Null or Undefined:** Check if a node's type allows for null or undefined values.
*   **Handle Small Integers (Smis):** Provide optimized operations for untagging Smis and checking if a value is a Smi.
*   **Convert to Float64:**  Safely convert values (numbers or oddballs) to 64-bit floating-point numbers, potentially adding type checks.
*   **Check Heap Object Types:** Generate nodes to verify if a value is a specific type of heap object (e.g., String, Number, Symbol, JSReceiver).
*   **Manage Object Maps:** Implement logic for checking the "map" (structure/layout) of objects, which is crucial for optimizing property access. This includes:
    *   Intersecting known possible maps of an object with a set of required maps.
    *   Generating `CheckMaps` nodes to ensure an object has one of the expected maps.
    *   Handling map migrations (changes to an object's structure).
*   **Handle Element Kind Transitions:**  Deal with changes to the internal representation of array elements.
*   **Compare Object Maps:** Generate code to branch based on whether an object's map matches a set of expected maps.
*   **Optimize Write Barriers:** Determine if a write barrier (a mechanism to inform the garbage collector about pointer updates) can be safely omitted during memory stores.
*   **Build Memory Store Operations:** Generate nodes for storing values into object fields, optionally with write barriers.
*   **Build Memory Load Operations:** Generate nodes for loading elements from `FixedArray`s.
*   **Track Object Changes (Virtual Objects):** Introduce a mechanism to track modifications to inlined allocations (objects created within a function), potentially optimizing subsequent loads and stores to those objects.

**Relationship to Javascript:**

The code deals with the underlying type system and memory management within the V8 JavaScript engine. While not directly representing JavaScript syntax, the type checks and object manipulations directly correspond to runtime checks and operations performed when executing JavaScript code.

**Example (JavaScript and Implied Maglev Operations):**

```javascript
function foo(x) {
  if (typeof x === 'number') { // Implies a type check
    return x + 1;              // Could involve Smi operations if x is a small integer
  } else if (typeof x === 'string') { // Another type check
    return x.length;             // Involves accessing a property of a String object
  }
  return null;
}

const obj = { a: 1 }; // Creates a JS object with a specific map
if (obj instanceof Object) { // Implies a map check (obj's map vs. Object's map)
  obj.b = 2;            // Implies a memory store operation, possibly with a write barrier
}
```

In the Maglev compiler, when processing the `typeof x === 'number'` check, the `MaglevGraphBuilder` would use functions like `BuildCheckNumber` or `CheckType` to generate nodes that verify the type of the `x` value. Accessing `x.length` would involve map checks to ensure `x` is a string and then a memory load operation to retrieve the `length` property.

**Code Logic and Assumptions:**

*   **Assumption:** The existence of helper functions like `StaticTypeForNode`, `NodeTypeIs`, `CombineType`, `IntersectType`, and potentially others not shown in the snippet.
*   **Implicit Input/Output:**  The functions operate on `ValueNode` objects, which represent values within the Maglev graph. The "input" is the `ValueNode` being examined, and the "output" is often a boolean indicating success or failure of a type check, or a modified `ValueNode` (e.g., after untagging a Smi). For functions that generate new nodes, the output is the newly created `Node`.

**User Programming Errors (Related to Type Checks):**

*   **Assuming a specific type without checking:**

    ```javascript
    function process(input) {
      return input.toUpperCase(); // Potential error if input is not a string
    }
    ```

    The Maglev compiler would insert checks (like `BuildCheckString`) before the `toUpperCase` operation to ensure `input` is indeed a string. If the check fails at runtime, a deoptimization might occur.

*   **Incorrect type assumptions in conditional logic:**

    ```javascript
    function calculate(value) {
      if (typeof value === 'number') {
        return value * 2;
      } else {
        return value.length; // Error if 'value' is not a string or array here
      }
    }
    ```

    If the `else` branch is reached with a `value` that doesn't have a `length` property, a runtime error will occur. Maglev's type tracking helps in generating more efficient code based on the expected types within these branches.

**归纳一下它的功能 (Summary of its Functionality):**

This part of `maglev-graph-builder.cc` is responsible for **implementing the type system and generating type-related operations within the Maglev compilation pipeline**. It provides the building blocks for:

*   **Inferring and asserting type information about values.**
*   **Generating code to perform runtime type checks.**
*   **Optimizing operations based on known types (e.g., Smi handling, write barrier elision).**
*   **Managing object structure (maps) and generating checks related to object layout.**
*   **Tracking changes to allocated objects for potential optimizations.**

In essence, it's a crucial component for ensuring type safety and enabling performance optimizations within the Maglev compiler by making type information explicit in the generated graph.

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
static_type = StaticTypeForNode(broker(), local_isolate(), node);
  if (current_type) *current_type = static_type;
  return NodeTypeIs(static_type, type);
}

bool MaglevGraphBuilder::EnsureType(ValueNode* node, NodeType type,
                                    NodeType* old_type) {
  if (CheckStaticType(node, type, old_type)) return true;
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  if (old_type) *old_type = known_info->type();
  if (NodeTypeIs(known_info->type(), type)) return true;
  known_info->CombineType(type);
  if (auto phi = node->TryCast<Phi>()) {
    known_info->CombineType(phi->type());
  }
  return false;
}

template <typename Function>
bool MaglevGraphBuilder::EnsureType(ValueNode* node, NodeType type,
                                    Function ensure_new_type) {
  if (CheckStaticType(node, type)) return true;
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  if (NodeTypeIs(known_info->type(), type)) return true;
  ensure_new_type(known_info->type());
  known_info->CombineType(type);
  return false;
}

void MaglevGraphBuilder::SetKnownValue(ValueNode* node, compiler::ObjectRef ref,
                                       NodeType new_node_type) {
  DCHECK(!node->Is<Constant>());
  DCHECK(!node->Is<RootConstant>());
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  // ref type should be compatible with type.
  DCHECK(NodeTypeIs(StaticTypeForConstant(broker(), ref), new_node_type));
  known_info->CombineType(new_node_type);
  known_info->alternative().set_checked_value(GetConstant(ref));
}

NodeType MaglevGraphBuilder::CheckTypes(ValueNode* node,
                                        std::initializer_list<NodeType> types) {
  auto it = known_node_aspects().FindInfo(node);
  bool has_kna = known_node_aspects().IsValid(it);
  for (NodeType type : types) {
    if (CheckStaticType(node, type)) return type;
    if (has_kna) {
      if (NodeTypeIs(it->second.type(), type)) return type;
    }
  }
  return NodeType::kUnknown;
}

bool MaglevGraphBuilder::CheckType(ValueNode* node, NodeType type,
                                   NodeType* current_type) {
  if (CheckStaticType(node, type, current_type)) return true;
  auto it = known_node_aspects().FindInfo(node);
  if (!known_node_aspects().IsValid(it)) return false;
  if (current_type) *current_type = it->second.type();
  return NodeTypeIs(it->second.type(), type);
}

NodeType MaglevGraphBuilder::GetType(ValueNode* node) {
  auto it = known_node_aspects().FindInfo(node);
  if (!known_node_aspects().IsValid(it)) {
    return StaticTypeForNode(broker(), local_isolate(), node);
  }
  NodeType actual_type = it->second.type();
  if (auto phi = node->TryCast<Phi>()) {
    actual_type = CombineType(actual_type, phi->type());
  }
#ifdef DEBUG
  NodeType static_type = StaticTypeForNode(broker(), local_isolate(), node);
  if (!NodeTypeIs(actual_type, static_type)) {
    // In case we needed a numerical alternative of a smi value, the type
    // must generalize. In all other cases the node info type should reflect the
    // actual type.
    DCHECK(static_type == NodeType::kSmi && actual_type == NodeType::kNumber &&
           !known_node_aspects().TryGetInfoFor(node)->alternative().has_none());
  }
#endif  // DEBUG
  return actual_type;
}

bool MaglevGraphBuilder::HaveDifferentTypes(ValueNode* lhs, ValueNode* rhs) {
  return HasDifferentType(lhs, GetType(rhs));
}

// Note: this is conservative, ie, returns true if {lhs} cannot be {rhs}.
// It might return false even if {lhs} is not {rhs}.
bool MaglevGraphBuilder::HasDifferentType(ValueNode* lhs, NodeType rhs_type) {
  NodeType lhs_type = GetType(lhs);
  if (lhs_type == NodeType::kUnknown || rhs_type == NodeType::kUnknown) {
    return false;
  }
  return IntersectType(lhs_type, rhs_type) == NodeType::kUnknown;
}

bool MaglevGraphBuilder::MayBeNullOrUndefined(ValueNode* node) {
  NodeType static_type = StaticTypeForNode(broker(), local_isolate(), node);
  if (!NodeTypeMayBeNullOrUndefined(static_type)) return false;
  auto it = known_node_aspects().FindInfo(node);
  if (!known_node_aspects().IsValid(it)) return true;
  return NodeTypeMayBeNullOrUndefined(it->second.type());
}

ValueNode* MaglevGraphBuilder::BuildSmiUntag(ValueNode* node) {
  if (EnsureType(node, NodeType::kSmi)) {
    if (SmiValuesAre31Bits()) {
      if (auto phi = node->TryCast<Phi>()) {
        phi->SetUseRequires31BitValue();
      }
    }
    return AddNewNode<UnsafeSmiUntag>({node});
  } else {
    return AddNewNode<CheckedSmiUntag>({node});
  }
}

namespace {
NodeType TaggedToFloat64ConversionTypeToNodeType(
    TaggedToFloat64ConversionType conversion_type) {
  switch (conversion_type) {
    case TaggedToFloat64ConversionType::kOnlyNumber:
      return NodeType::kNumber;
    case TaggedToFloat64ConversionType::kNumberOrBoolean:
      return NodeType::kNumberOrBoolean;
    case TaggedToFloat64ConversionType::kNumberOrOddball:
      return NodeType::kNumberOrOddball;
  }
}
}  // namespace

ValueNode* MaglevGraphBuilder::BuildNumberOrOddballToFloat64(
    ValueNode* node, TaggedToFloat64ConversionType conversion_type) {
  NodeType old_type;
  if (EnsureType(node, TaggedToFloat64ConversionTypeToNodeType(conversion_type),
                 &old_type)) {
    if (old_type == NodeType::kSmi) {
      ValueNode* untagged_smi = BuildSmiUntag(node);
      return AddNewNode<ChangeInt32ToFloat64>({untagged_smi});
    }
    return AddNewNode<UncheckedNumberOrOddballToFloat64>({node},
                                                         conversion_type);
  } else {
    return AddNewNode<CheckedNumberOrOddballToFloat64>({node}, conversion_type);
  }
}

ReduceResult MaglevGraphBuilder::BuildCheckSmi(ValueNode* object,
                                               bool elidable) {
  if (CheckStaticType(object, NodeType::kSmi)) return object;
  if (CheckType(object, NodeType::kAnyHeapObject)) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kNotASmi);
  }
  if (EnsureType(object, NodeType::kSmi) && elidable) return object;
  switch (object->value_representation()) {
    case ValueRepresentation::kInt32:
      if (!SmiValuesAre32Bits()) {
        AddNewNode<CheckInt32IsSmi>({object});
      }
      break;
    case ValueRepresentation::kUint32:
      AddNewNode<CheckUint32IsSmi>({object});
      break;
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      AddNewNode<CheckHoleyFloat64IsSmi>({object});
      break;
    case ValueRepresentation::kTagged:
      AddNewNode<CheckSmi>({object});
      break;
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  return object;
}

void MaglevGraphBuilder::BuildCheckHeapObject(ValueNode* object) {
  if (EnsureType(object, NodeType::kAnyHeapObject)) return;
  AddNewNode<CheckHeapObject>({object});
}

void MaglevGraphBuilder::BuildCheckString(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kString, &known_type)) return;
  AddNewNode<CheckString>({object}, GetCheckType(known_type));
}

void MaglevGraphBuilder::BuildCheckStringOrStringWrapper(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kStringOrStringWrapper, &known_type)) return;
  AddNewNode<CheckStringOrStringWrapper>({object}, GetCheckType(known_type));
}

void MaglevGraphBuilder::BuildCheckNumber(ValueNode* object) {
  if (EnsureType(object, NodeType::kNumber)) return;
  AddNewNode<CheckNumber>({object}, Object::Conversion::kToNumber);
}

void MaglevGraphBuilder::BuildCheckSymbol(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kSymbol, &known_type)) return;
  AddNewNode<CheckSymbol>({object}, GetCheckType(known_type));
}

void MaglevGraphBuilder::BuildCheckJSReceiver(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kJSReceiver, &known_type)) return;
  AddNewNode<CheckInstanceType>({object}, GetCheckType(known_type),
                                FIRST_JS_RECEIVER_TYPE, LAST_JS_RECEIVER_TYPE);
}

namespace {

class KnownMapsMerger {
 public:
  explicit KnownMapsMerger(compiler::JSHeapBroker* broker, Zone* zone,
                           base::Vector<const compiler::MapRef> requested_maps)
      : broker_(broker), zone_(zone), requested_maps_(requested_maps) {}

  void IntersectWithKnownNodeAspects(
      ValueNode* object, const KnownNodeAspects& known_node_aspects) {
    auto node_info_it = known_node_aspects.FindInfo(object);
    bool has_node_info = known_node_aspects.IsValid(node_info_it);
    NodeType type =
        has_node_info ? node_info_it->second.type() : NodeType::kUnknown;
    if (has_node_info && node_info_it->second.possible_maps_are_known()) {
      // TODO(v8:7700): Make intersection non-quadratic.
      for (compiler::MapRef possible_map :
           node_info_it->second.possible_maps()) {
        if (std::find(requested_maps_.begin(), requested_maps_.end(),
                      possible_map) != requested_maps_.end()) {
          // No need to add dependencies, we already have them for all known
          // possible maps.
          // Filter maps which are impossible given this objects type. Since we
          // want to prove that an object with map `map` is not an instance of
          // `type`, we cannot use `StaticTypeForMap`, as it only provides an
          // approximation. This filtering is done to avoid creating
          // non-sensical types later (e.g. if we think only a non-string map
          // is possible, after a string check).
          if (IsInstanceOfNodeType(possible_map, type, broker_)) {
            InsertMap(possible_map);
          }
        } else {
          known_maps_are_subset_of_requested_maps_ = false;
        }
      }
      if (intersect_set_.is_empty()) {
        node_type_ = NodeType::kUnknown;
      }
    } else {
      // A missing entry here means the universal set, i.e., we don't know
      // anything about the possible maps of the object. Intersect with the
      // universal set, which means just insert all requested maps.
      known_maps_are_subset_of_requested_maps_ = false;
      existing_known_maps_found_ = false;
      for (compiler::MapRef map : requested_maps_) {
        InsertMap(map);
      }
    }
  }

  void UpdateKnownNodeAspects(ValueNode* object,
                              KnownNodeAspects& known_node_aspects) {
    // Update known maps.
    auto node_info = known_node_aspects.GetOrCreateInfoFor(
        object, broker_, broker_->local_isolate());
    node_info->SetPossibleMaps(intersect_set_, any_map_is_unstable_, node_type_,
                               broker_);
    // Make sure known_node_aspects.any_map_for_any_node_is_unstable is updated
    // in case any_map_is_unstable changed to true for this object -- this can
    // happen if this was an intersection with the universal set which added new
    // possible unstable maps.
    if (any_map_is_unstable_) {
      known_node_aspects.any_map_for_any_node_is_unstable = true;
    }
    // At this point, known_node_aspects.any_map_for_any_node_is_unstable may be
    // true despite there no longer being any unstable maps for any nodes (if
    // this was the only node with unstable maps and this intersection removed
    // those). This is ok, because that's at worst just an overestimate -- we
    // could track whether this node's any_map_is_unstable flipped from true to
    // false, but this is likely overkill.
    // Insert stable map dependencies which weren't inserted yet. This is only
    // needed if our set of known maps was empty and we created it anew based on
    // maps we checked.
    if (!existing_known_maps_found_) {
      for (compiler::MapRef map : intersect_set_) {
        if (map.is_stable()) {
          broker_->dependencies()->DependOnStableMap(map);
        }
      }
    } else {
      // TODO(victorgomes): Add a DCHECK_SLOW that checks if the maps already
      // exist in the CompilationDependencySet.
    }
  }

  bool known_maps_are_subset_of_requested_maps() const {
    return known_maps_are_subset_of_requested_maps_;
  }
  bool emit_check_with_migration() const { return emit_check_with_migration_; }

  const compiler::ZoneRefSet<Map>& intersect_set() const {
    return intersect_set_;
  }

  NodeType node_type() const { return node_type_; }

 private:
  compiler::JSHeapBroker* broker_;
  Zone* zone_;
  base::Vector<const compiler::MapRef> requested_maps_;
  compiler::ZoneRefSet<Map> intersect_set_;
  bool known_maps_are_subset_of_requested_maps_ = true;
  bool existing_known_maps_found_ = true;
  bool emit_check_with_migration_ = false;
  bool any_map_is_unstable_ = false;
  NodeType node_type_ = static_cast<NodeType>(-1);

  Zone* zone() const { return zone_; }

  void InsertMap(compiler::MapRef map) {
    if (map.is_migration_target()) {
      emit_check_with_migration_ = true;
    }
    NodeType new_type = StaticTypeForMap(map, broker_);
    if (new_type == NodeType::kHeapNumber) {
      new_type = IntersectType(new_type, NodeType::kSmi);
    }
    node_type_ = IntersectType(node_type_, new_type);
    if (!map.is_stable()) {
      any_map_is_unstable_ = true;
    }
    intersect_set_.insert(map, zone());
  }
};

}  // namespace

ReduceResult MaglevGraphBuilder::BuildCheckMaps(
    ValueNode* object, base::Vector<const compiler::MapRef> maps,
    std::optional<ValueNode*> map) {
  // TODO(verwaest): Support other objects with possible known stable maps as
  // well.
  if (compiler::OptionalHeapObjectRef constant = TryGetConstant(object)) {
    // For constants with stable maps that match one of the desired maps, we
    // don't need to emit a map check, and can use the dependency -- we
    // can't do this for unstable maps because the constant could migrate
    // during compilation.
    compiler::MapRef constant_map = constant.value().map(broker());
    if (std::find(maps.begin(), maps.end(), constant_map) != maps.end()) {
      if (constant_map.is_stable()) {
        broker()->dependencies()->DependOnStableMap(constant_map);
        return ReduceResult::Done();
      }
      // TODO(verwaest): Reduce maps to the constant map.
    } else {
      // TODO(leszeks): Insert an unconditional deopt if the constant map
      // doesn't match the required map.
    }
  }

  NodeInfo* known_info = GetOrCreateInfoFor(object);

  // Calculates if known maps are a subset of maps, their map intersection and
  // whether we should emit check with migration.
  KnownMapsMerger merger(broker(), zone(), maps);
  merger.IntersectWithKnownNodeAspects(object, known_node_aspects());

  // If the known maps are the subset of the maps to check, we are done.
  if (merger.known_maps_are_subset_of_requested_maps()) {
    // The node type of known_info can get out of sync with the possible maps.
    // For instance after merging with an effectively dead branch (i.e., check
    // contradicting all possible maps).
    // TODO(olivf) Try to combine node_info and possible maps and ensure that
    // narrowing the type also clears impossible possible_maps.
    if (!NodeTypeIs(known_info->type(), merger.node_type())) {
      known_info->IntersectType(merger.node_type());
    }
#ifdef DEBUG
    // Double check that, for every possible map, it's one of the maps we'd
    // want to check.
    for (compiler::MapRef map :
         known_node_aspects().TryGetInfoFor(object)->possible_maps()) {
      DCHECK_NE(std::find(maps.begin(), maps.end(), map), maps.end());
    }
#endif
    return ReduceResult::Done();
  }

  if (merger.intersect_set().is_empty()) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kWrongMap);
  }

  // TODO(v8:7700): Check if the {maps} - {known_maps} size is smaller than
  // {maps} \intersect {known_maps}, we can emit CheckNotMaps instead.

  // Emit checks.
  if (merger.emit_check_with_migration()) {
    AddNewNode<CheckMapsWithMigration>({object}, merger.intersect_set(),
                                       GetCheckType(known_info->type()));
  } else if (map) {
    AddNewNode<CheckMapsWithAlreadyLoadedMap>({object, *map},
                                              merger.intersect_set());
  } else {
    AddNewNode<CheckMaps>({object}, merger.intersect_set(),
                          GetCheckType(known_info->type()));
  }

  merger.UpdateKnownNodeAspects(object, known_node_aspects());
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildTransitionElementsKindOrCheckMap(
    ValueNode* heap_object, ValueNode* object_map,
    const ZoneVector<compiler::MapRef>& transition_sources,
    compiler::MapRef transition_target) {
  // TODO(marja): Optimizations based on what we know about the intersection of
  // known maps and transition sources or transition target.

  // TransitionElementsKind doesn't happen in cases where we'd need to do
  // CheckMapsWithMigration instead of CheckMaps.
  CHECK(!transition_target.is_migration_target());
  for (const compiler::MapRef transition_source : transition_sources) {
    CHECK(!transition_source.is_migration_target());
  }

  NodeInfo* known_info = GetOrCreateInfoFor(heap_object);

  AddNewNode<TransitionElementsKindOrCheckMap>(
      {heap_object, object_map}, transition_sources, transition_target);
  // After this operation, heap_object's map is transition_target (or we
  // deopted).
  known_info->SetPossibleMaps(
      PossibleMaps{transition_target}, !transition_target.is_stable(),
      StaticTypeForMap(transition_target, broker()), broker());
  DCHECK(transition_target.IsJSReceiverMap());
  if (!transition_target.is_stable()) {
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    broker()->dependencies()->DependOnStableMap(transition_target);
  }
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildCompareMaps(
    ValueNode* heap_object, ValueNode* object_map,
    base::Vector<const compiler::MapRef> maps, MaglevSubGraphBuilder* sub_graph,
    std::optional<MaglevSubGraphBuilder::Label>& if_not_matched) {
  GetOrCreateInfoFor(heap_object);
  KnownMapsMerger merger(broker(), zone(), maps);
  merger.IntersectWithKnownNodeAspects(heap_object, known_node_aspects());

  if (merger.intersect_set().is_empty()) {
    return ReduceResult::DoneWithAbort();
  }

  // TODO(pthier): Support map packing.
  DCHECK(!V8_MAP_PACKING_BOOL);

  // TODO(pthier): Handle map migrations.
  std::optional<MaglevSubGraphBuilder::Label> map_matched;
  const compiler::ZoneRefSet<Map>& relevant_maps = merger.intersect_set();
  if (relevant_maps.size() > 1) {
    map_matched.emplace(sub_graph, static_cast<int>(relevant_maps.size()));
    for (size_t map_index = 1; map_index < relevant_maps.size(); map_index++) {
      sub_graph->GotoIfTrue<BranchIfReferenceEqual>(
          &*map_matched,
          {object_map, GetConstant(relevant_maps.at(map_index))});
    }
  }
  if_not_matched.emplace(sub_graph, 1);
  sub_graph->GotoIfFalse<BranchIfReferenceEqual>(
      &*if_not_matched, {object_map, GetConstant(relevant_maps.at(0))});
  if (map_matched.has_value()) {
    sub_graph->Goto(&*map_matched);
    sub_graph->Bind(&*map_matched);
  }
  merger.UpdateKnownNodeAspects(heap_object, known_node_aspects());
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildTransitionElementsKindAndCompareMaps(
    ValueNode* heap_object, ValueNode* object_map,
    const ZoneVector<compiler::MapRef>& transition_sources,
    compiler::MapRef transition_target, MaglevSubGraphBuilder* sub_graph,
    std::optional<MaglevSubGraphBuilder::Label>& if_not_matched) {
  DCHECK(!transition_target.is_migration_target());

  NodeInfo* known_info = GetOrCreateInfoFor(heap_object);

  // TODO(pthier): Calculate and use the intersection of known maps with
  // (transition_sources union transition_target).

  ValueNode* new_map = AddNewNode<TransitionElementsKind>(
      {heap_object, object_map}, transition_sources, transition_target);

  // TODO(pthier): Support map packing.
  DCHECK(!V8_MAP_PACKING_BOOL);
  if_not_matched.emplace(sub_graph, 1);
  sub_graph->GotoIfFalse<BranchIfReferenceEqual>(
      &*if_not_matched, {new_map, GetConstant(transition_target)});
  // After the branch, object's map is transition_target.
  DCHECK(transition_target.IsJSReceiverMap());
  known_info->SetPossibleMaps(
      PossibleMaps{transition_target}, !transition_target.is_stable(),
      StaticTypeForMap(transition_target, broker()), broker());
  if (!transition_target.is_stable()) {
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    broker()->dependencies()->DependOnStableMap(transition_target);
  }
  return ReduceResult::Done();
}

namespace {
AllocationBlock* GetAllocation(ValueNode* object) {
  if (object->Is<InlinedAllocation>()) {
    object = object->Cast<InlinedAllocation>()->input(0).node();
  }
  if (object->Is<AllocationBlock>()) {
    return object->Cast<AllocationBlock>();
  }
  return nullptr;
}
}  // namespace

bool MaglevGraphBuilder::CanElideWriteBarrier(ValueNode* object,
                                              ValueNode* value) {
  if (value->Is<RootConstant>()) return true;
  if (CheckType(value, NodeType::kSmi)) {
    RecordUseReprHintIfPhi(value, UseRepresentation::kTagged);
    return true;
  }

  // No need for a write barrier if both object and value are part of the same
  // folded young allocation.
  AllocationBlock* allocation = GetAllocation(object);
  if (allocation != nullptr &&
      allocation->allocation_type() == AllocationType::kYoung &&
      allocation == GetAllocation(value)) {
    return true;
  }

  // If tagged and not Smi, we cannot elide write barrier.
  if (value->is_tagged()) return false;

  // If its alternative conversion node is Smi, {value} will be converted to
  // a Smi when tagged.
  NodeInfo* node_info = GetOrCreateInfoFor(value);
  if (ValueNode* tagged_alt = node_info->alternative().tagged()) {
    DCHECK(tagged_alt->properties().is_conversion());
    return CheckType(tagged_alt, NodeType::kSmi);
  }
  return false;
}

void MaglevGraphBuilder::BuildInitializeStore(InlinedAllocation* object,
                                              ValueNode* value, int offset) {
  const bool value_is_trusted = value->Is<TrustedConstant>();
  DCHECK(value->is_tagged());
  if (InlinedAllocation* inlined_value = value->TryCast<InlinedAllocation>()) {
    // Add to the escape set.
    auto escape_deps = graph()->allocations_escape_map().find(object);
    CHECK(escape_deps != graph()->allocations_escape_map().end());
    escape_deps->second.push_back(inlined_value);
    // Add to the elided set.
    auto& elided_map = graph()->allocations_elide_map();
    auto elided_deps = elided_map.try_emplace(inlined_value, zone()).first;
    elided_deps->second.push_back(object);
    inlined_value->AddNonEscapingUses();
  }
  if (value_is_trusted) {
    BuildStoreTrustedPointerField(object, value, offset,
                                  value->Cast<TrustedConstant>()->tag(),
                                  StoreTaggedMode::kInitializing);
  } else {
    BuildStoreTaggedField(object, value, offset,
                          StoreTaggedMode::kInitializing);
  }
}

namespace {
bool IsEscaping(Graph* graph, InlinedAllocation* alloc) {
  if (alloc->IsEscaping()) return true;
  auto it = graph->allocations_elide_map().find(alloc);
  if (it == graph->allocations_elide_map().end()) return false;
  for (InlinedAllocation* inner_alloc : it->second) {
    if (IsEscaping(graph, inner_alloc)) {
      return true;
    }
  }
  return false;
}

bool VerifyIsNotEscaping(VirtualObject::List vos, InlinedAllocation* alloc) {
  for (VirtualObject* vo : vos) {
    if (vo->type() != VirtualObject::kDefault) continue;
    if (vo->allocation() == alloc) continue;
    for (uint32_t i = 0; i < vo->slot_count(); i++) {
      ValueNode* nested_value = vo->get_by_index(i);
      if (!nested_value->Is<InlinedAllocation>()) continue;
      ValueNode* nested_alloc = nested_value->Cast<InlinedAllocation>();
      if (nested_alloc == alloc) {
        if (vo->allocation()->IsEscaping()) return false;
        if (!VerifyIsNotEscaping(vos, vo->allocation())) return false;
      }
    }
  }
  return true;
}
}  // namespace

bool MaglevGraphBuilder::CanTrackObjectChanges(ValueNode* receiver,
                                               TrackObjectMode mode) {
  DCHECK(!receiver->Is<VirtualObject>());
  if (!v8_flags.maglev_object_tracking) return false;
  if (!receiver->Is<InlinedAllocation>()) return false;
  InlinedAllocation* alloc = receiver->Cast<InlinedAllocation>();
  if (mode == TrackObjectMode::kStore) {
    // If we have two objects A and B, such that A points to B (it contains B in
    // one of its field), we cannot change B without also changing A, even if
    // both can be elided. For now, we escape both objects instead.
    if (graph_->allocations_elide_map().find(alloc) !=
        graph_->allocations_elide_map().end()) {
      return false;
    }
    if (alloc->IsEscaping()) return false;
    // Ensure object is escaped if we are within a try-catch block. This is
    // crucial because a deoptimization point inside the catch handler could
    // re-materialize objects differently, depending on whether the throw
    // occurred before or after this store. We could potentially relax this
    // requirement by verifying that no throwable nodes have been emitted since
    // the try-block started,  but for now, err on the side of caution and
    // always escape.
    if (IsInsideTryBlock()) return false;
  } else {
    DCHECK_EQ(mode, TrackObjectMode::kLoad);
    if (IsEscaping(graph_, alloc)) return false;
  }
  // We don't support loop phis inside VirtualObjects, so any access inside a
  // loop should escape the object, except for objects that were created since
  // the last loop header.
  if (IsInsideLoop()) {
    if (!is_loop_effect_tracking() ||
        !loop_effects_->allocations.contains(alloc)) {
      return false;
    }
  }
  // Iterate all live objects to be sure that the allocation is not escaping.
  SLOW_DCHECK(
      VerifyIsNotEscaping(current_interpreter_frame_.virtual_objects(), alloc));
  return true;
}

VirtualObject* MaglevGraphBuilder::GetObjectFromAllocation(
    InlinedAllocation* allocation) {
  VirtualObject* vobject = allocation->object();
  // If it hasn't be snapshotted yet, it is the latest created version of this
  // object, we don't need to search for it.
  if (vobject->IsSnapshot()) {
    vobject = current_interpreter_frame_.virtual_objects().FindAllocatedWith(
        allocation);
  }
  return vobject;
}

VirtualObject* MaglevGraphBuilder::GetModifiableObjectFromAllocation(
    InlinedAllocation* allocation) {
  VirtualObject* vobject = allocation->object();
  // If it hasn't be snapshotted yet, it is the latest created version of this
  // object and we can still modify it, we don't need to copy it.
  if (vobject->IsSnapshot()) {
    return DeepCopyVirtualObject(
        current_interpreter_frame_.virtual_objects().FindAllocatedWith(
            allocation));
  }
  return vobject;
}

void MaglevGraphBuilder::TryBuildStoreTaggedFieldToAllocation(ValueNode* object,
                                                              ValueNode* value,
                                                              int offset) {
  if (offset == HeapObject::kMapOffset) return;
  if (!CanTrackObjectChanges(object, TrackObjectMode::kStore)) return;
  // This avoids loop in the object graph.
  if (value->Is<InlinedAllocation>()) return;
  InlinedAllocation* allocation = object->Cast<InlinedAllocation>();
  VirtualObject* vobject = GetModifiableObjectFromAllocation(allocation);
  CHECK_EQ(vobject->type(), VirtualObject::kDefault);
  CHECK_NOT_NULL(vobject);
  vobject->set(offset, value);
  AddNonEscapingUses(allocation, 1);
  if (v8_flags.trace_maglev_object_tracking) {
    std::cout << "  * Setting value in virtual object "
              << PrintNodeLabel(graph_labeller(), vobject) << "[" << offset
              << "]: " << PrintNode(graph_labeller(), value) << std::endl;
  }
}

Node* MaglevGraphBuilder::BuildStoreTaggedField(ValueNode* object,
                                                ValueNode* value, int offset,
                                                StoreTaggedMode store_mode) {
  // The value may be used to initialize a VO, which can leak to IFS.
  // It should NOT be a conversion node, UNLESS it's an initializing value.
  // Initializing values are tagged before allocation, since conversion nodes
  // may allocate, and are not used to set a VO.
  DCHECK_IMPLIES(store_mode != StoreTaggedMode::kInitializing,
                 !value->properties().is_conversion());
  if (store_mode != StoreTaggedMode::kInitializing) {
    TryBuildStoreTaggedFieldToAllocation(object, value, offset);
  }
  if (CanElideWriteBarrier(object, value)) {
    return AddNewNode<StoreTaggedFieldNoWriteBarrier>({object, value}, offset,
                                                      store_mode);
  } else {
    return AddNewNode<StoreTaggedFieldWithWriteBarrier>({object, value}, offset,
                                                        store_mode);
  }
}

void MaglevGraphBuilder::BuildStoreTaggedFieldNoWriteBarrier(
    ValueNode* object, ValueNode* value, int offset,
    StoreTaggedMode store_mode) {
  // The value may be used to initialize a VO, which can leak to IFS.
  // It should NOT be a conversion node, UNLESS it's an initializing value.
  // Initializing values are tagged before allocation, since conversion nodes
  // may allocate, and are not used to set a VO.
  DCHECK_IMPLIES(store_mode != StoreTaggedMode::kInitializing,
                 !value->properties().is_conversion());
  DCHECK(CanElideWriteBarrier(object, value));
  if (store_mode != StoreTaggedMode::kInitializing) {
    TryBuildStoreTaggedFieldToAllocation(object, value, offset);
  }
  AddNewNode<StoreTaggedFieldNoWriteBarrier>({object, value}, offset,
                                             store_mode);
}

void MaglevGraphBuilder::BuildStoreTrustedPointerField(
    ValueNode* object, ValueNode* value, int offset, IndirectPointerTag tag,
    StoreTaggedMode store_mode) {
#ifdef V8_ENABLE_SANDBOX
  AddNewNode<StoreTrustedPointerFieldWithWriteBarrier>({object, value}, offset,
                                                       tag, store_mode);
#else
  BuildStoreTaggedField(object, value, offset, store_mode);
#endif  // V8_ENABLE_SANDBOX
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedArrayElement(ValueNode* elements,
                                                          int index) {
  compiler::OptionalHeapObjectRef maybe_constant;
  if ((maybe_constant = TryGetConstant(elements)) &&
      maybe_constant.value().IsFixedArray()) {
    compiler::FixedArrayRef fixed_array_ref =
        maybe_constant.value().AsFixedArray();
    if (index >= 0 && static_cast<uint32_t>(index) < fixed_array_ref.length()) {
      compiler::OptionalObjectRef maybe_value =
          fixed_array_ref.TryGet(broker(), index);
      if (maybe_value) return GetConstant(*maybe_value);
    } else {
      return GetRootConstant(RootIndex::kTheHoleValue);
    }
  }
  if (CanTrackObjectChanges(elements, TrackObjectMode::kLoad)) {
    VirtualObject* vobject =
        GetObjectFromAllocation(elements->Cast<InlinedAllocation>());
    CHECK_EQ(vobject->type(), VirtualObject::kDefault);
    DCHECK(vobject->map().IsFixedArrayMap());
    ValueNode* length_node = vobject->get(offsetof(FixedArray, length_));
    if (auto length = TryGetInt32Constant(length_node)) {
      if (index >= 0 && index < length.value()) {
        return vobject->get(FixedArray::OffsetOfElementAt(index));
      } else {
        return GetRootConstant(RootIndex::kTheHoleValue);
      }
    }
  }
  if (index < 0 || index >= FixedArray::kMaxLength) {
    return GetRootConstant(RootIndex::kTheHoleValue);
  }
  return AddNewNode<LoadTaggedField>({elements},
                                     FixedArray::OffsetOfElementAt(index));
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedArrayElement(ValueNode* elements,
                                                          ValueNode* index) {
  if (auto constant = TryGetInt32Constant(index)) {
    return BuildLoadFixedArrayElement(elements, constant.value());
  }
  return AddNewNode<LoadFixedArrayElement>({elements, index});
}

void MaglevGraphBuilder::BuildStoreFixedArrayElement(ValueNode* elements,
                                                     ValueNode* index,
                                                     ValueNode* value) {
  // TODO(victorgomes): Support storing element to a virtual object. If we
  // modify the elements array, we need to modify the original object to point
  // to the new elements array.
  if (CanElideWriteBarrier(elements, value)) {
    AddNewNo
```