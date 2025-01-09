Response:
Let's break down the thought process for analyzing the provided C++ code and generating the response.

1. **Understand the Goal:** The request asks for a functional breakdown of the `type-visitor.cc` file within the V8 Torque compiler. It also requests connections to JavaScript, examples, logical reasoning scenarios, and common errors.

2. **Initial Skim and Keywords:** Quickly read through the code, looking for key terms and patterns:
    * `TypeVisitor`: This is the central class, so its methods will likely define the core functionality.
    * `ComputeType`:  Appears repeatedly, suggesting the main responsibility is determining types.
    * `TypeDeclaration`, `TypeAliasDeclaration`, `AbstractTypeDeclaration`, `StructDeclaration`, `ClassDeclaration`, `BitFieldStructDeclaration`:  These indicate the different kinds of types the visitor handles.
    * `TypeOracle`:  Suggests a central registry or manager for types.
    * `Declarations`:  Implies managing declared entities (types, functions, etc.).
    * `Signature`:  Related to function/method signatures.
    * `Error`, `ReportError`, `Lint`: Indicate error handling and static analysis.
    * `MaybeSpecializationKey`:  Points to handling generic types.
    * `Scope`, `CurrentScope`: Suggests managing lexical scopes for type resolution.
    * `JavaScript`, `TNode`: Specific terms linking to the broader V8 context.

3. **Identify Core Functionality (Central Question: What does this code *do*?):**  Focus on the `ComputeType` methods. Notice they handle different `TypeDeclaration` subtypes. This immediately suggests the file's primary role is to determine the concrete `Type` object represented by various syntactic type declarations in the Torque language.

4. **Break Down `ComputeType` Methods (How does it do it?):**  Examine each overloaded `ComputeType` method:
    * **`ComputeType(TypeDeclaration*, ...)`:** The entry point, dispatching based on the `decl->kind`.
    * **`ComputeType(TypeAliasDeclaration*, ...)`:** Handles simple type renaming.
    * **`ComputeType(AbstractTypeDeclaration*, ...)`:** Deals with abstract types, inheritance, and `generates` clauses (related to C++ type generation).
    * **`ComputeType(BitFieldStructDeclaration*, ...)`:** Manages bit-packed structures, including size and bit allocation.
    * **`ComputeType(StructDeclaration*, ...)`:**  Handles regular structures, field layout, and offsets.
    * **`ComputeType(ClassDeclaration*, ...)`:** The most complex, dealing with classes, inheritance, flags (like `extern`, `shape`), and potentially C++ code generation.
    * **`ComputeType(TypeExpression*)`:**  Handles parsing type expressions (basic types, unions, function types).

5. **Identify Supporting Functions:** Look for other important functions:
    * `DeclareMethods`:  Registers methods within a struct or class.
    * `MakeSignature`: Creates a `Signature` object from a `CallableDeclaration`.
    * `VisitClassFieldsAndMethods`, `VisitStructMethods`:  Handle the processing of fields and methods within classes and structs after the basic type structure is established.
    * `ComputeTypeForStructExpression`: Specifically for resolving the type of struct literals/initializations, including handling generics.

6. **Connect to JavaScript (Why is this relevant?):**  Think about how Torque relates to JavaScript. Torque is used to generate optimized runtime code for V8 (the JavaScript engine). Focus on the following connections:
    * **Type System:** Torque defines a type system that interacts with JavaScript's.
    * **`TNode`:**  A key concept for representing JavaScript values within the generated code. The `generates` clause is crucial here.
    * **Optimizations:**  Torque helps optimize common JavaScript operations.

7. **Provide JavaScript Examples:** Create simple JavaScript scenarios that illustrate the Torque type concepts:
    * Basic types (number, string, boolean).
    * Objects (relate to structs/classes).
    * Functions.
    * The idea of optimization (though direct demonstration in JavaScript is hard).

8. **Logical Reasoning Scenarios (What if...?):**  Invent simple hypothetical Torque code snippets and trace the expected behavior of the `TypeVisitor`. Focus on:
    * Type aliases.
    * Struct field ordering and offsets.
    * Class inheritance.
    * Generic type instantiation.

9. **Identify Common Programming Errors (Where can things go wrong?):**  Think about typical mistakes developers might make when defining types in a language like Torque:
    * Type mismatches.
    * Invalid inheritance.
    * Incorrect field definitions (especially bitfields).
    * Generic type errors (wrong number or type of arguments).

10. **Structure the Response:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core functionalities (the `ComputeType` methods).
    * Explain supporting functions.
    * Connect to JavaScript with examples.
    * Provide logical reasoning scenarios.
    * List common programming errors.
    * Conclude with the relationship to Torque and V8.

11. **Refine and Elaborate:** Go back through the response, adding details and clarifying any ambiguous points. Ensure consistent terminology. For example, emphasize that Torque is *not* JavaScript but a DSL for V8 development. Explain the significance of `TNode`.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just figures out types."  **Correction:**  It's more than just looking up types. It involves creating type objects, handling inheritance, generics, and flags, and preparing information for code generation.
* **Initial JavaScript example idea:**  Trying to directly show `TNode` manipulation in JS. **Correction:**  This is too low-level. Focus on the higher-level JavaScript concepts that Torque types represent.
* **Logical reasoning too complex:** Starting with very intricate type relationships. **Correction:** Simplify the examples to illustrate one or two key concepts at a time.

By following this structured approach, combining code analysis with an understanding of the surrounding context (Torque and V8), and iteratively refining the explanation, a comprehensive and accurate answer can be generated.
This C++ source code file, `v8/src/torque/type-visitor.cc`, is a crucial part of the **Torque type system** within the V8 JavaScript engine. Torque is a domain-specific language (DSL) used to write optimized built-in functions for V8. The `TypeVisitor` class is responsible for **analyzing and computing the types** defined in Torque source code.

Here's a breakdown of its functionalities:

**Core Functionality: Computing Types**

The primary responsibility of `TypeVisitor` is to traverse the Abstract Syntax Tree (AST) of Torque type declarations and determine the corresponding `Type` objects. This involves:

* **Handling various type declarations:**  It has specific `ComputeType` methods for different kinds of type declarations in Torque, such as:
    * `TypeAliasDeclaration`: For creating aliases (synonyms) for existing types.
    * `AbstractTypeDeclaration`: For defining abstract base types.
    * `StructDeclaration`: For defining structures (collections of fields).
    * `ClassDeclaration`: For defining classes with inheritance, methods, and fields.
    * `BitFieldStructDeclaration`: For defining structures where fields are packed into bits.
* **Resolving type names:** It looks up declared types and handles namespace qualifications.
* **Handling generic types:** It supports instantiation of generic types with specific type arguments.
* **Inferring types:** In some cases, it can infer types based on usage or context.
* **Managing specialization:** It deals with creating specialized versions of generic types.
* **Building `Type` objects:** It uses the `TypeOracle` (another Torque component) to create and manage the actual `Type` objects in the type system.
* **Error checking:** It performs various checks for type consistency and validity, reporting errors for issues like:
    * Trying to extend a union type.
    * Defining a transient type as constexpr.
    * Using constexpr types in struct fields.
    * Invalid bitfield definitions.
    * Class inheritance issues.

**Key Functions and Their Roles:**

* **`ComputeType(TypeDeclaration* decl, ...)`:** The main entry point for computing the type of a declaration. It dispatches to specific `ComputeType` methods based on the kind of declaration.
* **`ComputeType(TypeAliasDeclaration* decl, ...)`:** Computes the type of a type alias.
* **`ComputeType(AbstractTypeDeclaration* decl, ...)`:** Computes the type of an abstract type, handling inheritance and the `generates` clause (which often specifies the corresponding C++ type).
* **`ComputeType(BitFieldStructDeclaration* decl, ...)`:** Computes the type of a bitfield struct, carefully managing bit offsets and sizes.
* **`ComputeType(StructDeclaration* decl, ...)`:** Computes the type of a regular struct, determining field offsets.
* **`ComputeType(ClassDeclaration* decl, ...)`:** Computes the type of a class, handling inheritance, flags (like `extern`, `shape`), and method declarations.
* **`ComputeType(TypeExpression* type_expression)`:** Computes the type represented by a type expression in Torque code (e.g., `Foo`, `List<Bar>`, `(Number, String) => Boolean`).
* **`MakeSignature(const CallableDeclaration* declaration)`:** Creates a `Signature` object representing the parameter and return types of a Torque function or macro.
* **`VisitClassFieldsAndMethods(...)`:**  Processes the fields and methods declared within a class, calculating offsets and registering them with the `ClassType`.
* **`VisitStructMethods(...)`:** Processes the methods declared within a struct.
* **`ComputeTypeForStructExpression(...)`:**  Specifically handles determining the type of a struct being instantiated, especially when dealing with generic structs.

**Relationship to JavaScript and Examples**

While `v8/src/torque/type-visitor.cc` is a C++ file within V8's internals, it directly relates to how JavaScript code is optimized. Torque is used to define the optimized implementations of built-in JavaScript functions and objects.

* **Torque Types and JavaScript Concepts:** Torque types often correspond to internal representations of JavaScript values. For instance:
    * A Torque `Number` type might correspond to V8's internal representation of JavaScript numbers.
    * A Torque `String` type would relate to V8's string representation.
    * Torque classes like `JSObject` directly represent JavaScript objects.

* **`generates` Clause:** The `generates` clause in Torque type declarations (especially for abstract types and classes) often specifies the underlying C++ type that will be used to represent these values in the generated code. This is how Torque bridges the gap between its high-level type system and V8's C++ implementation.

**JavaScript Examples (illustrating the *concepts* Torque is defining):**

```javascript
// Example related to Torque's Structs/Classes
class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
  }
}

let p = new Point(10, 20);
console.log(p.x); // Accessing a field

// Example related to Type Aliases (conceptually)
/**
 * @typedef {number} Age
 */
let myAge = 30; // 'Age' is like an alias for 'number'

// Example related to Union Types (conceptually)
/**
 * @param {number | string} input
 */
function processInput(input) {
  if (typeof input === 'number') {
    console.log("It's a number:", input);
  } else {
    console.log("It's a string:", input);
  }
}

processInput(42);
processInput("hello");
```

**How `TypeVisitor` Contributes to Optimization:**

By meticulously defining and checking types in Torque, the `TypeVisitor` ensures that the generated C++ code can make assumptions about the types of values it's working with. This enables significant optimizations:

* **Specialized Code Generation:** Torque can generate different, more efficient code paths based on the specific types involved in an operation.
* **Elimination of Type Checks:** If the type system guarantees a value is of a certain type, runtime type checks can be avoided.
* **Improved Memory Layout:** Torque allows control over the memory layout of objects (through structs and classes), leading to better cache locality.

**Logical Reasoning with Hypothetical Torque Code:**

Let's imagine a simplified Torque type declaration:

```torque
// Hypothetical Torque code
type MyPoint = struct {
  x: int32;
  y: int32;
}
```

**Input to `TypeVisitor`:** The AST representing this `MyPoint` struct declaration.

**Processing by `TypeVisitor`:**

1. The `ComputeType(TypeDeclaration* decl, ...)` method would be called.
2. It would identify the declaration as a `StructDeclaration`.
3. `ComputeType(StructDeclaration* decl, ...)` would be invoked.
4. The visitor would process each field:
   - For `x: int32`, it would look up the `int32` type.
   - For `y: int32`, it would look up the `int32` type.
5. It would calculate the offsets of the fields (assuming no padding, `x` at offset 0, `y` at offset 4 on a 32-bit system).
6. The `TypeOracle` would be used to create a `StructType` object for `MyPoint`, containing information about its fields and their offsets.

**Output of `TypeVisitor`:** A `StructType` object representing `MyPoint`. This object would store information like the field names (`x`, `y`), their types (`int32`), and their memory offsets.

**User-Common Programming Errors (in Torque, which helps prevent runtime errors in JavaScript):**

While users don't directly write `v8/src/torque/type-visitor.cc` code, understanding its purpose helps understand potential errors when *writing Torque code* that this visitor would catch:

1. **Type Mismatches:**
   ```torque
   // Error: Trying to assign a string to an int32 field
   type MyData = struct {
     count: int32;
   }
   var data: MyData = { count: "hello" }; // TypeVisitor would flag this
   ```
   This is analogous to trying to assign the wrong type in JavaScript, but Torque enforces stricter type checking during compilation.

2. **Invalid Inheritance:**
   ```torque
   // Error: Trying to extend a non-class type
   type MyAlias = int32;
   type MyDerived = class extends MyAlias {}; // TypeVisitor would flag this
   ```
   Similar to JavaScript's class inheritance rules, Torque enforces that you can only extend classes.

3. **Incorrect Bitfield Definitions:**
   ```torque
   // Error: Asking for more bits than the underlying type allows
   type MyBits = bitfield struct (uint8) {
     flag1: bool : 4; // Error: bool only needs 1 bit
   }
   ```
   The `TypeVisitor` checks that the number of bits specified for bitfields is valid for the underlying type.

4. **Using `constexpr` incorrectly:**
   ```torque
   // Error: Trying to have a constexpr field in a regular struct
   type MyConstexpr = constexpr int32;
   type MyStruct = struct {
     value: MyConstexpr; // TypeVisitor would likely flag this
   }
   ```
   Torque has specific rules about where `constexpr` types can be used.

**In summary, `v8/src/torque/type-visitor.cc` is a fundamental component of the Torque compiler responsible for understanding and validating the types defined in Torque source code. This process is crucial for generating optimized and type-safe C++ code that implements V8's built-in functionalities, ultimately making JavaScript execution faster and more reliable.**

Prompt: 
```
这是目录为v8/src/torque/type-visitor.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/type-visitor.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/type-visitor.h"

#include <optional>

#include "src/common/globals.h"
#include "src/torque/declarable.h"
#include "src/torque/global-context.h"
#include "src/torque/kythe-data.h"
#include "src/torque/server-data.h"
#include "src/torque/type-inference.h"
#include "src/torque/type-oracle.h"

namespace v8::internal::torque {

const Type* TypeVisitor::ComputeType(TypeDeclaration* decl,
                                     MaybeSpecializationKey specialized_from,
                                     Scope* specialization_requester) {
  SourcePosition requester_position = CurrentSourcePosition::Get();
  CurrentSourcePosition::Scope scope(decl->pos);
  Scope* current_scope = CurrentScope::Get();
  if (specialized_from) {
    current_scope = TypeOracle::CreateGenericTypeInstantiationNamespace();
    current_scope->SetSpecializationRequester(
        {requester_position, specialization_requester,
         Type::ComputeName(decl->name->value, specialized_from)});
  }
  CurrentScope::Scope new_current_scope_scope(current_scope);
  if (specialized_from) {
    auto& params = specialized_from->generic->generic_parameters();
    auto arg_types_iterator = specialized_from->specialized_types.begin();
    for (auto param : params) {
      TypeAlias* alias =
          Declarations::DeclareType(param.name, *arg_types_iterator);
      alias->SetIsUserDefined(false);
      arg_types_iterator++;
    }
  }

  switch (decl->kind) {
#define ENUM_ITEM(name)        \
  case AstNode::Kind::k##name: \
    return ComputeType(name::cast(decl), specialized_from);
    AST_TYPE_DECLARATION_NODE_KIND_LIST(ENUM_ITEM)
#undef ENUM_ITEM
    default:
      UNIMPLEMENTED();
  }
}

const Type* TypeVisitor::ComputeType(TypeAliasDeclaration* decl,
                                     MaybeSpecializationKey specialized_from) {
  const Type* type = ComputeType(decl->type);
  type->AddAlias(decl->name->value);
  return type;
}

namespace {
std::string ComputeGeneratesType(std::optional<std::string> opt_gen,
                                 bool enforce_tnode_type) {
  if (!opt_gen) return "";
  const std::string& generates = *opt_gen;
  if (enforce_tnode_type) {
    return UnwrapTNodeTypeName(generates);
  }
  return generates;
}
}  // namespace

const AbstractType* TypeVisitor::ComputeType(
    AbstractTypeDeclaration* decl, MaybeSpecializationKey specialized_from) {
  std::string generates =
      ComputeGeneratesType(decl->generates, !decl->IsConstexpr());

  const Type* parent_type = nullptr;
  if (decl->extends) {
    parent_type = TypeVisitor::ComputeType(*decl->extends);
    if (parent_type->IsUnionType()) {
      // UnionType::IsSupertypeOf requires that types can only extend from non-
      // union types in order to work correctly.
      ReportError("type \"", decl->name->value,
                  "\" cannot extend a type union");
    }
  }

  if (decl->IsConstexpr() && decl->IsTransient()) {
    ReportError("cannot declare a transient type that is also constexpr");
  }

  const Type* non_constexpr_version = nullptr;
  if (decl->IsConstexpr()) {
    QualifiedName non_constexpr_name{GetNonConstexprName(decl->name->value)};
    if (auto type = Declarations::TryLookupType(non_constexpr_name)) {
      non_constexpr_version = *type;
    }
  }

  return TypeOracle::GetAbstractType(parent_type, decl->name->value,
                                     decl->flags, generates,
                                     non_constexpr_version, specialized_from);
}

void DeclareMethods(AggregateType* container_type,
                    const std::vector<Declaration*>& methods) {
  for (auto declaration : methods) {
    CurrentSourcePosition::Scope pos_scope(declaration->pos);
    TorqueMacroDeclaration* method =
        TorqueMacroDeclaration::DynamicCast(declaration);
    Signature signature = TypeVisitor::MakeSignature(method);
    signature.parameter_names.insert(
        signature.parameter_names.begin() + signature.implicit_count,
        MakeNode<Identifier>(kThisParameterName));
    Statement* body = *(method->body);
    const std::string& method_name(method->name->value);
    signature.parameter_types.types.insert(
        signature.parameter_types.types.begin() + signature.implicit_count,
        container_type);
    Method* m = Declarations::CreateMethod(container_type, method_name,
                                           signature, body);
    m->SetPosition(method->pos);
    m->SetIdentifierPosition(method->name->pos);
  }
}

const BitFieldStructType* TypeVisitor::ComputeType(
    BitFieldStructDeclaration* decl, MaybeSpecializationKey specialized_from) {
  CurrentSourcePosition::Scope position_scope(decl->pos);
  if (specialized_from.has_value()) {
    ReportError("Bitfield struct specialization is not supported");
  }
  const Type* parent = TypeVisitor::ComputeType(decl->parent);
  if (!IsAnyUnsignedInteger(parent)) {
    ReportError(
        "Bitfield struct must extend from an unsigned integer type, not ",
        parent->ToString());
  }
  auto opt_size = SizeOf(parent);
  if (!opt_size.has_value()) {
    ReportError("Cannot determine size of bitfield struct ", decl->name->value,
                " because of unsized parent type ", parent->ToString());
  }
  const size_t size = 8 * std::get<0>(*opt_size);  // Convert bytes to bits.
  BitFieldStructType* type = TypeOracle::GetBitFieldStructType(parent, decl);

  // Iterate through all of the declared fields, checking their validity and
  // registering them on the newly-constructed BitFieldStructType instance.
  int offset = 0;
  for (const auto& field : decl->fields) {
    CurrentSourcePosition::Scope field_position_scope(
        field.name_and_type.type->pos);
    const Type* field_type = TypeVisitor::ComputeType(field.name_and_type.type);
    if (!IsAllowedAsBitField(field_type)) {
      ReportError("Type not allowed as bitfield: ",
                  field.name_and_type.name->value);
    }

    // Compute the maximum number of bits that could be used for a field of this
    // type. Booleans are a special case, not included in SizeOf, because their
    // runtime size is 32 bits but they should only occupy 1 bit as a bitfield.
    size_t field_type_size = 0;
    if (field_type->IsSubtypeOf(TypeOracle::GetBoolType())) {
      field_type_size = 1;
    } else {
      auto opt_field_type_size = SizeOf(field_type);
      if (!opt_field_type_size.has_value()) {
        ReportError("Size unknown for type ", field_type->ToString());
      }
      field_type_size = 8 * std::get<0>(*opt_field_type_size);
    }

    if (field.num_bits < 1 ||
        static_cast<size_t>(field.num_bits) > field_type_size) {
      ReportError("Invalid number of bits for ",
                  field.name_and_type.name->value);
    }
    type->RegisterField({field.name_and_type.name->pos,
                         {field.name_and_type.name->value, field_type},
                         offset,
                         field.num_bits});
    offset += field.num_bits;
    if (static_cast<size_t>(offset) > size) {
      ReportError("Too many total bits in ", decl->name->value);
    }
  }

  return type;
}

const StructType* TypeVisitor::ComputeType(
    StructDeclaration* decl, MaybeSpecializationKey specialized_from) {
  StructType* struct_type = TypeOracle::GetStructType(decl, specialized_from);
  CurrentScope::Scope struct_namespace_scope(struct_type->nspace());
  CurrentSourcePosition::Scope decl_position_activator(decl->pos);

  ResidueClass offset = 0;
  for (auto& field : decl->fields) {
    CurrentSourcePosition::Scope position_activator(
        field.name_and_type.type->pos);
    const Type* field_type = TypeVisitor::ComputeType(field.name_and_type.type);
    if (field_type->IsConstexpr()) {
      ReportError("struct field \"", field.name_and_type.name->value,
                  "\" carries constexpr type \"", *field_type, "\"");
    }
    Field f{field.name_and_type.name->pos,
            struct_type,
            std::nullopt,
            {field.name_and_type.name->value, field_type},
            offset.SingleValue(),
            false,
            field.const_qualified,
            FieldSynchronization::kNone};
    auto optional_size = SizeOf(f.name_and_type.type);
    struct_type->RegisterField(f);
    // Offsets are assigned based on an assumption of no space between members.
    // This might lead to invalid alignment in some cases, but most structs are
    // never actually packed in memory together (they just represent a batch of
    // CSA TNode values that should be passed around together). For any struct
    // that is used as a class field, we verify its offsets when setting up the
    // class type.
    if (optional_size.has_value()) {
      size_t field_size = 0;
      std::tie(field_size, std::ignore) = *optional_size;
      offset += field_size;
    } else {
      // Structs may contain fields that aren't representable in packed form. If
      // so, the offset of subsequent fields are marked as invalid.
      offset = ResidueClass::Unknown();
    }
  }
  return struct_type;
}

const ClassType* TypeVisitor::ComputeType(
    ClassDeclaration* decl, MaybeSpecializationKey specialized_from) {
  // TODO(sigurds): Remove this hack by introducing a declarable for classes.
  const TypeAlias* alias =
      Declarations::LookupTypeAlias(QualifiedName(decl->name->value));
  DCHECK_EQ(*alias->delayed_, decl);
  ClassFlags flags = decl->flags;
  bool is_shape = flags & ClassFlag::kIsShape;
  std::string generates = decl->name->value;
  const Type* super_type = TypeVisitor::ComputeType(decl->super);
  if (is_shape) {
    if (!(flags & ClassFlag::kExtern)) {
      ReportError("Shapes must be extern, add \"extern\" to the declaration.");
    }
    if (flags & ClassFlag::kUndefinedLayout) {
      ReportError("Shapes need to define their layout.");
    }
    const ClassType* super_class = ClassType::DynamicCast(super_type);
    if (!super_class ||
        !super_class->IsSubtypeOf(TypeOracle::GetJSObjectType())) {
      Error("Shapes need to extend a subclass of ",
            *TypeOracle::GetJSObjectType())
          .Throw();
    }
    // Shapes use their super class in CSA code since they have incomplete
    // support for type-checks on the C++ side.
    generates = super_class->name();
  }
  if (super_type != TypeOracle::GetStrongTaggedType()) {
    const ClassType* super_class = ClassType::DynamicCast(super_type);
    if (!super_class) {
      ReportError(
          "class \"", decl->name->value,
          "\" must extend either StrongTagged or an already declared class");
    }
    if (super_class->HasUndefinedLayout() &&
        !(flags & ClassFlag::kUndefinedLayout)) {
      Error("Class \"", decl->name->value,
            "\" defines its layout but extends a class which does not")
          .Position(decl->pos);
    }
    if ((flags & ClassFlag::kExport) &&
        !(super_class->ShouldExport() || super_class->IsExtern())) {
      Error("cannot export class ", decl->name,
            " because superclass is neither @export or extern");
    }
  }
  if ((flags & ClassFlag::kGenerateBodyDescriptor ||
       flags & ClassFlag::kExport) &&
      flags & ClassFlag::kUndefinedLayout) {
    Error("Class \"", decl->name->value,
          "\" requires a layout but doesn't have one");
  }
  if (flags & ClassFlag::kGenerateUniqueMap) {
    if (!(flags & ClassFlag::kExtern)) {
      Error("No need to specify ", ANNOTATION_GENERATE_UNIQUE_MAP,
            ", non-extern classes always have a unique map.");
    }
    if (flags & ClassFlag::kAbstract) {
      Error(ANNOTATION_ABSTRACT, " and ", ANNOTATION_GENERATE_UNIQUE_MAP,
            " shouldn't be used together, because abstract classes are never "
            "instantiated.");
    }
  }
  if ((flags & ClassFlag::kGenerateFactoryFunction) &&
      (flags & ClassFlag::kAbstract)) {
    Error(ANNOTATION_ABSTRACT, " and ", ANNOTATION_GENERATE_FACTORY_FUNCTION,
          " shouldn't be used together, because abstract classes are never "
          "instantiated.");
  }
  if (flags & ClassFlag::kExtern) {
    if (decl->generates) {
      bool enforce_tnode_type = true;
      std::string explicit_generates =
          ComputeGeneratesType(decl->generates, enforce_tnode_type);
      if (explicit_generates == generates) {
        Lint("Unnecessary 'generates' clause for class ", decl->name->value);
      }
      generates = explicit_generates;
    }
    if (flags & ClassFlag::kExport) {
      Error("cannot export a class that is marked extern");
    }
  } else {
    if (decl->generates) {
      ReportError("Only extern classes can specify a generated type.");
    }
    if (super_type != TypeOracle::GetStrongTaggedType()) {
      if (flags & ClassFlag::kUndefinedLayout) {
        Error("non-external classes must have defined layouts");
      }
    }
  }
  if (!(flags & ClassFlag::kExtern) &&
      (flags & ClassFlag::kHasSameInstanceTypeAsParent)) {
    Error("non-extern Torque-defined classes must have unique instance types");
  }
  if ((flags & ClassFlag::kHasSameInstanceTypeAsParent) &&
      !(flags & ClassFlag::kDoNotGenerateCast || flags & ClassFlag::kIsShape)) {
    Error(
        "classes that inherit their instance type must be annotated with "
        "@doNotGenerateCast");
  }

  return TypeOracle::GetClassType(super_type, decl->name->value, flags,
                                  generates, decl, alias);
}

const Type* TypeVisitor::ComputeType(TypeExpression* type_expression) {
  if (auto* basic = BasicTypeExpression::DynamicCast(type_expression)) {
    QualifiedName qualified_name{basic->namespace_qualification,
                                 basic->name->value};
    auto& args = basic->generic_arguments;
    const Type* type;
    SourcePosition pos = SourcePosition::Invalid();

    if (args.empty()) {
      auto* alias = Declarations::LookupTypeAlias(qualified_name);
      type = alias->type();
      pos = alias->GetDeclarationPosition();
      if (GlobalContext::collect_kythe_data()) {
        if (alias->IsUserDefined()) {
          KytheData::AddTypeUse(basic->name->pos, alias);
        }
      }
    } else {
      auto* generic_type =
          Declarations::LookupUniqueGenericType(qualified_name);
      type = TypeOracle::GetGenericTypeInstance(generic_type,
                                                ComputeTypeVector(args));
      pos = generic_type->declaration()->name->pos;
      if (GlobalContext::collect_kythe_data()) {
        KytheData::AddTypeUse(basic->name->pos, generic_type);
      }
    }

    if (GlobalContext::collect_language_server_data()) {
      LanguageServerData::AddDefinition(type_expression->pos, pos);
    }
    return type;
  }
  if (auto* union_type = UnionTypeExpression::DynamicCast(type_expression)) {
    return TypeOracle::GetUnionType(ComputeType(union_type->a),
                                    ComputeType(union_type->b));
  }
  if (auto* function_type_exp =
          FunctionTypeExpression::DynamicCast(type_expression)) {
    TypeVector argument_types;
    for (TypeExpression* type_exp : function_type_exp->parameters) {
      argument_types.push_back(ComputeType(type_exp));
    }
    return TypeOracle::GetBuiltinPointerType(
        std::move(argument_types), ComputeType(function_type_exp->return_type));
  }
  auto* precomputed = PrecomputedTypeExpression::cast(type_expression);
  return precomputed->type;
}

Signature TypeVisitor::MakeSignature(const CallableDeclaration* declaration) {
  LabelDeclarationVector definition_vector;
  for (const auto& label : declaration->labels) {
    LabelDeclaration def = {label.name, ComputeTypeVector(label.types)};
    definition_vector.push_back(def);
  }
  std::optional<std::string> arguments_variable;
  if (declaration->parameters.has_varargs)
    arguments_variable = declaration->parameters.arguments_variable;
  Signature result{declaration->parameters.names,
                   arguments_variable,
                   {ComputeTypeVector(declaration->parameters.types),
                    declaration->parameters.has_varargs},
                   declaration->parameters.implicit_count,
                   ComputeType(declaration->return_type),
                   definition_vector,
                   declaration->transitioning};
  return result;
}

void TypeVisitor::VisitClassFieldsAndMethods(
    ClassType* class_type, const ClassDeclaration* class_declaration) {
  const ClassType* super_class = class_type->GetSuperClass();
  ResidueClass class_offset = 0;
  size_t header_size = 0;
  if (super_class) {
    class_offset = super_class->size();
    header_size = super_class->header_size();
  }

  for (const ClassFieldExpression& field_expression :
       class_declaration->fields) {
    CurrentSourcePosition::Scope position_activator(
        field_expression.name_and_type.type->pos);
    const Type* field_type = ComputeType(field_expression.name_and_type.type);
    if (class_type->IsShape()) {
      if (!field_type->IsSubtypeOf(TypeOracle::GetObjectType())) {
        ReportError(
            "in-object properties only support subtypes of Object, but "
            "found type ",
            *field_type);
      }
      if (field_expression.custom_weak_marking) {
        ReportError("in-object properties cannot use @customWeakMarking");
      }
    }
    std::optional<ClassFieldIndexInfo> array_length = field_expression.index;
    const Field& field = class_type->RegisterField(
        {field_expression.name_and_type.name->pos,
         class_type,
         array_length,
         {field_expression.name_and_type.name->value, field_type},
         class_offset.SingleValue(),
         field_expression.custom_weak_marking,
         field_expression.const_qualified,
         field_expression.synchronization});
    ResidueClass field_size = std::get<0>(field.GetFieldSizeInformation());
    if (field.index) {
      // Validate that a value at any index in a packed array is aligned
      // correctly, since it is possible to define a struct whose size is not a
      // multiple of its alignment.
      field.ValidateAlignment(class_offset +
                              field_size * ResidueClass::Unknown());

      if (auto literal =
              IntegerLiteralExpression::DynamicCast(field.index->expr)) {
        if (auto value = literal->value.TryTo<size_t>()) {
          field_size *= *value;
        } else {
          Error("Not a valid field index").Position(field.pos);
        }
      } else {
        field_size *= ResidueClass::Unknown();
      }
    }
    field.ValidateAlignment(class_offset);
    class_offset += field_size;
    // In-object properties are not considered part of the header.
    if (class_offset.SingleValue() && !class_type->IsShape()) {
      header_size = *class_offset.SingleValue();
    }
    if (!field.index && !class_offset.SingleValue()) {
      Error("Indexed fields have to be at the end of the object")
          .Position(field.pos);
    }
  }
  DCHECK_GT(header_size, 0);
  class_type->header_size_ = header_size;
  class_type->size_ = class_offset;
  class_type->GenerateAccessors();
  DeclareMethods(class_type, class_declaration->methods);
}

void TypeVisitor::VisitStructMethods(
    StructType* struct_type, const StructDeclaration* struct_declaration) {
  DeclareMethods(struct_type, struct_declaration->methods);
}

const Type* TypeVisitor::ComputeTypeForStructExpression(
    TypeExpression* type_expression,
    const std::vector<const Type*>& term_argument_types) {
  auto* basic = BasicTypeExpression::DynamicCast(type_expression);
  if (!basic) {
    ReportError("expected basic type expression referring to struct");
  }

  QualifiedName qualified_name{basic->namespace_qualification,
                               basic->name->value};
  std::optional<GenericType*> maybe_generic_type =
      Declarations::TryLookupGenericType(qualified_name);

  StructDeclaration* decl =
      maybe_generic_type
          ? StructDeclaration::DynamicCast((*maybe_generic_type)->declaration())
          : nullptr;

  // Compute types of non-generic structs as usual
  if (!(maybe_generic_type && decl)) {
    const Type* type = ComputeType(type_expression);
    if (!type->IsStructType() && !type->IsBitFieldStructType()) {
      ReportError(*type,
                  " is not a struct or bitfield struct, but used like one");
    }
    return type;
  }

  auto generic_type = *maybe_generic_type;
  auto explicit_type_arguments = ComputeTypeVector(basic->generic_arguments);

  std::vector<TypeExpression*> term_parameters;
  auto& fields = decl->fields;
  term_parameters.reserve(fields.size());
  for (auto& field : fields) {
    term_parameters.push_back(field.name_and_type.type);
  }

  CurrentScope::Scope generic_scope(generic_type->ParentScope());
  TypeArgumentInference inference(
      generic_type->generic_parameters(), explicit_type_arguments,
      term_parameters,
      TransformVector<std::optional<const Type*>>(term_argument_types));

  if (inference.HasFailed()) {
    ReportError("failed to infer type arguments for struct ", basic->name,
                " initialization: ", inference.GetFailureReason());
  }
  if (GlobalContext::collect_language_server_data()) {
    LanguageServerData::AddDefinition(type_expression->pos,
                                      generic_type->declaration()->name->pos);
  }
  return StructType::cast(
      TypeOracle::GetGenericTypeInstance(generic_type, inference.GetResult()));
}

}  // namespace v8::internal::torque

"""

```