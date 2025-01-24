Response:
The user wants a summary of the provided C++ code, which is part of the V8 JavaScript engine's Torque compiler.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core functionality:** The filename "types.cc" and the included headers like `src/torque/ast.h`, `src/torque/declarable.h`, and `src/torque/type-oracle.h` strongly suggest this file is responsible for defining and managing the type system within Torque.

2. **Examine the `Type` class:** This is the central class. Note its constructors, methods like `ToString`, `SimpleName`, `IsSubtypeOf`, and the nested `UnionType`, `StructType`, and `ClassType`. This confirms the file deals with various types.

3. **Analyze key methods and their implications:**
    * `ToString`, `SimpleName`: These are for representing types as strings, important for debugging and code generation.
    * `IsSubtypeOf`: This indicates the type system supports inheritance or a similar concept.
    * `GetConstexprGeneratedTypeName`, `GetGeneratedTypeName`, `GetGeneratedTNodeTypeName`:  These methods suggest the code is involved in generating C++ code representations of Torque types, crucial for the final compilation step. The mention of "TNode" is a hint about V8's internal representation of JavaScript objects.
    * `CommonSupertype`:  This points to the ability to find the least common ancestor of two types in the type hierarchy.

4. **Focus on derived type classes:**  The existence of `UnionType`, `StructType`, `BitFieldStructType`, `AggregateType`, and `ClassType` indicates a rich type system with different kinds of composite types.

5. **Look for connections to JavaScript:**  The mention of `Tagged`, `Smi`, `HeapNumber`, `BigInt`, `Object` within the `UnionType` implementation strongly links these Torque types to JavaScript's fundamental data types. The `Handle` and `DirectHandle` mentions further connect to V8's object management.

6. **Identify code generation aspects:** The presence of methods like `GenerateAccessors` and `GenerateSliceAccessor` within `ClassType`, along with the usage of `MakeIdentifierExpression`, `MakeFieldAccessExpression`, etc., clearly indicates code generation for accessing fields and data within objects.

7. **Consider potential user errors:** The `AggregateType::CheckForDuplicateFields` method hints at a common programming error related to naming conflicts in classes or structs.

8. **Structure the summary:** Organize the findings into logical categories: Core Functionality, Type Representation, Type Relationships, Code Generation, JavaScript Connection, Error Prevention.

9. **Refine the language:** Use clear and concise language, avoiding jargon where possible, and relating the code's function to the broader context of a compiler for a language like JavaScript. For example, "mapping Torque types to C++" is more understandable than just "generating C++ code."

10. **Address the prompt's specifics:**  Ensure the summary explicitly mentions:
    * Whether the file is a Torque source file (yes, based on the `.cc` extension and content, despite the prompt's hypothetical `.tq`).
    * The relationship to JavaScript.
    * Potential user errors.
    * Code logic inference (subtype relationships, common supertype).

By following this process, the detailed summary can be generated. The iterative refinement of understanding the code's purpose and the connections between different parts is key.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/types.h"

#include <cmath>
#include <iostream>
#include <optional>

#include "src/base/bits.h"
#include "src/torque/ast.h"
#include "src/torque/declarable.h"
#include "src/torque/global-context.h"
#include "src/torque/source-positions.h"
#include "src/torque/type-oracle.h"
#include "src/torque/type-visitor.h"

namespace v8::internal::torque {

// This custom copy constructor doesn't copy aliases_ and id_ because they
// should be distinct for each type.
Type::Type(const Type& other) V8_NOEXCEPT
    : TypeBase(other),
      parent_(other.parent_),
      aliases_(),
      id_(TypeOracle::FreshTypeId()),
      constexpr_version_(other.constexpr_version_) {}
Type::Type(TypeBase::Kind kind, const Type* parent,
           MaybeSpecializationKey specialized_from)
    : TypeBase(kind),
      parent_(parent),
      id_(TypeOracle::FreshTypeId()),
      specialized_from_(specialized_from),
      constexpr_version_(nullptr) {}

std::string Type::ToString() const {
  if (aliases_.empty())
    return ComputeName(ToExplicitString(), GetSpecializedFrom());
  if (aliases_.size() == 1) return *aliases_.begin();
  std::stringstream result;
  int i = 0;
  for (const std::string& alias : aliases_) {
    if (i == 0) {
      result << alias << " (aka. ";
    } else if (i == 1) {
      result << alias;
    } else {
      result << ", " << alias;
    }
    ++i;
  }
  result << ")";
  return result.str();
}

std::string Type::SimpleName() const {
  if (aliases_.empty()) {
    std::stringstream result;
    result << SimpleNameImpl();
    if (GetSpecializedFrom()) {
      for (const Type* t : GetSpecializedFrom()->specialized_types) {
        result << "_" << t->SimpleName();
      }
    }
    return result.str();
  }
  return *aliases_.begin();
}

std::string Type::GetHandleTypeName(HandleKind kind,
                                    const std::string& type_name) const {
  switch (kind) {
    case HandleKind::kIndirect:
      return "Handle<" + type_name + ">";
    case HandleKind::kDirect:
      return "DirectHandle<" + type_name + ">";
  }
}

// TODO(danno): HandlifiedCppTypeName should be used universally in Torque
// where the C++ type of a Torque object is required.
std::string Type::HandlifiedCppTypeName(HandleKind kind) const {
  if (IsSubtypeOf(TypeOracle::GetSmiType())) return "int";
  if (IsSubtypeOf(TypeOracle::GetTaggedType())) {
    return GetHandleTypeName(kind, GetConstexprGeneratedTypeName());
  } else {
    return GetConstexprGeneratedTypeName();
  }
}

std::string Type::TagglifiedCppTypeName() const {
  if (IsSubtypeOf(TypeOracle::GetSmiType())) return "int";
  if (IsSubtypeOf(TypeOracle::GetTaggedType())) {
    return "Tagged<" + GetConstexprGeneratedTypeName() + ">";
  } else {
    return GetConstexprGeneratedTypeName();
  }
}

bool Type::IsSubtypeOf(const Type* supertype) const {
  if (supertype->IsTopType()) return true;
  if (IsNever()) return true;
  if (const UnionType* union_type = UnionType::DynamicCast(supertype)) {
    return union_type->IsSupertypeOf(this);
  }
  const Type* subtype = this;
  while (subtype != nullptr) {
    if (subtype == supertype) return true;
    subtype = subtype->parent();
  }
  return false;
}

std::string Type::GetConstexprGeneratedTypeName() const {
  const Type* constexpr_version = ConstexprVersion();
  if (constexpr_version == nullptr) {
    Error("Type '", ToString(), "' requires a constexpr representation");
    return "";
  }
  return constexpr_version->GetGeneratedTypeName();
}

std::optional<const ClassType*> Type::ClassSupertype() const {
  for (const Type* t = this; t != nullptr; t = t->parent()) {
    if (auto* class_type = ClassType::DynamicCast(t)) {
      return class_type;
    }
  }
  return std::nullopt;
}

std::optional<const StructType*> Type::StructSupertype() const {
  for (const Type* t = this; t != nullptr; t = t->parent()) {
    if (auto* struct_type = StructType::DynamicCast(t)) {
      return struct_type;
    }
  }
  return std::nullopt;
}

std::optional<const AggregateType*> Type::AggregateSupertype() const {
  for (const Type* t = this; t != nullptr; t = t->parent()) {
    if (auto* aggregate_type = AggregateType::DynamicCast(t)) {
      return aggregate_type;
    }
  }
  return std::nullopt;
}

// static
const Type* Type::CommonSupertype(const Type* a, const Type* b) {
  int diff = a->Depth() - b->Depth();
  const Type* a_supertype = a;
  const Type* b_supertype = b;
  for (; diff > 0; --diff) a_supertype = a_supertype->parent();
  for (; diff < 0; ++diff) b_supertype = b_supertype->parent();
  while (a_supertype && b_supertype) {
    if (a_supertype == b_supertype) return a_supertype;
    a_supertype = a_supertype->parent();
    b_supertype = b_supertype->parent();
  }
  ReportError("types " + a->ToString() + " and " + b->ToString() +
              " have no common supertype");
}

int Type::Depth() const {
  int result = 0;
  for (const Type* current = parent_; current; current = current->parent_) {
    ++result;
  }
  return result;
}

bool Type::IsAbstractName(const std::string& name) const {
  if (!IsAbstractType()) return false;
  return AbstractType::cast(this)->name() == name;
}

std::string Type::GetGeneratedTypeName() const {
  std::string result = GetGeneratedTypeNameImpl();
  if (result.empty() || result == "TNode<>") {
    ReportError("Generated type is required for type '", ToString(),
                "'. Use 'generates' clause in definition.");
  }
  return result;
}

std::string Type::GetGeneratedTNodeTypeName() const {
  std::string result = GetGeneratedTNodeTypeNameImpl();
  if (result.empty() || IsConstexpr()) {
    ReportError("Generated TNode type is required for type '", ToString(),
                "'. Use 'generates' clause in definition.");
  }
  return result;
}

std::string AbstractType::GetGeneratedTypeNameImpl() const {
  // A special case that is not very well represented by the "generates"
  // syntax in the .tq files: Lazy<T> represents a std::function that
  // produces a TNode of the wrapped type.
  if (std::optional<const Type*> type_wrapped_in_lazy =
          Type::MatchUnaryGeneric(this, TypeOracle::GetLazyGeneric())) {
    DCHECK(!IsConstexpr());
    return "std::function<" + (*type_wrapped_in_lazy)->GetGeneratedTypeName() +
           "()>";
  }

  if (generated_type_.empty()) {
    return parent()->GetGeneratedTypeName();
  }
  return IsConstexpr() ? generated_type_ : "TNode<" + generated_type_ + ">";
}

std::string AbstractType::GetGeneratedTNodeTypeNameImpl() const {
  if (generated_type_.empty()) return parent()->GetGeneratedTNodeTypeName();
  return generated_type_;
}

std::vector<TypeChecker> AbstractType::GetTypeCheckers() const {
  if (UseParentTypeChecker()) return parent()->GetTypeCheckers();
  std::string type_name = name();
  if (auto strong_type =
          Type::MatchUnaryGeneric(this, TypeOracle::GetWeakGeneric())) {
    auto strong_runtime_types = (*strong_type)->GetTypeCheckers();
    std::vector<TypeChecker> result;
    for (const TypeChecker& type : strong_runtime_types) {
      // Generic parameter in Weak<T> should have already been checked to
      // extend HeapObject, so it couldn't itself be another weak type.
      DCHECK(type.weak_ref_to.empty());
      result.push_back({type_name, type.type});
    }
    return result;
  }
  return {{type_name, ""}};
}

std::string BuiltinPointerType::ToExplicitString() const {
  std::stringstream result;
  result << "builtin (";
  PrintCommaSeparatedList(result, parameter_types_);
  result << ") => " << *return_type_;
  return result.str();
}

std::string BuiltinPointerType::SimpleNameImpl() const {
  std::stringstream result;
  result << "BuiltinPointer";
  for (const Type* t : parameter_types_) {
    result << "_" << t->SimpleName();
  }
  result << "_" << return_type_->SimpleName();
  return result.str();
}

std::string UnionType::ToExplicitString() const {
  std::stringstream result;
  result << "(";
  bool first = true;
  for (const Type* t : types_) {
    if (!first) {
      result << " | ";
    }
    first = false;
    result << *t;
  }
  result << ")";
  return result.str();
}

std::string UnionType::SimpleNameImpl() const {
  std::stringstream result;
  bool first = true;
  for (const Type* t : types_) {
    if (!first) {
      result << "_OR_";
    }
    first = false;
    result << t->SimpleName();
  }
  return result.str();
}

std::string UnionType::GetGeneratedTNodeTypeNameImpl() const {
  if (types_.size() <= 3) {
    std::set<std::string> members;
    for (const Type* t : types_) {
      members.insert(t->GetGeneratedTNodeTypeName());
    }
    if (members == std::set<std::string>{"Smi", "HeapNumber"}) {
      return "Number";
    }
    if (members == std::set<std::string>{"Smi", "HeapNumber", "BigInt"}) {
      return "Numeric";
    }
  }
  return parent()->GetGeneratedTNodeTypeName();
}

std::string UnionType::GetRuntimeType() const {
  for (const Type* t : types_) {
    if (!t->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      return parent()->GetRuntimeType();
    }
  }
  return "Tagged<" + GetConstexprGeneratedTypeName() + ">";
}

// static
void UnionType::InsertConstexprGeneratedTypeName(std::set<std::string>& names,
                                                 const Type* t) {
  if (t->IsUnionType()) {
    for (const Type* u : ((const UnionType*)t)->types_) {
      names.insert(u->GetConstexprGeneratedTypeName());
    }
  } else {
    names.insert(t->GetConstexprGeneratedTypeName());
  }
}

std::string UnionType::GetConstexprGeneratedTypeName() const {
  // For non-tagged unions, use the superclass GetConstexprGeneratedTypeName.
  for (const Type* t : types_) {
    if (!t->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      return this->Type::GetConstexprGeneratedTypeName();
    }
  }

  // Allow some aliased simple names to be used as-is.
  std::string simple_name = SimpleName();
  if (simple_name == "Object") return simple_name;
  if (simple_name == "Number") return simple_name;
  if (simple_name == "Numeric") return simple_name;
  if (simple_name == "JSAny") return simple_name;
  if (simple_name == "JSPrimitive") return simple_name;

  // Deduplicate generated typenames and flatten unions.
  std::set<std::string> names;
  for (const Type* t : types_) {
    InsertConstexprGeneratedTypeName(names, t);
  }
  std::stringstream result;
  result << "Union<";
  bool first = true;
  for (std::string name : names) {
    if (!first) {
      result << ", ";
    }
    first = false;
    result << name;
  }
  result << ">";
  return result.str();
}

std::string UnionType::GetDebugType() const { return parent()->GetDebugType(); }

void UnionType::RecomputeParent() {
  const Type* parent = nullptr;
  for (const Type* t : types_) {
    if (parent == nullptr) {
      parent = t;
    } else {
      parent = CommonSupertype(parent, t);
    }
  }
  set_parent(parent);
}

void UnionType::Subtract(const Type* t) {
  for (auto it = types_.begin(); it != types_.end();) {
    if ((*it)->IsSubtypeOf(t)) {
      it = types_.erase(it);
    } else {
      ++it;
    }
  }
  if (types_.empty()) types_.insert(TypeOracle::GetNeverType());
  RecomputeParent();
}

const Type* SubtractType(const Type* a, const Type* b) {
  UnionType result = UnionType::FromType(a);
  result.Subtract(b);
  return TypeOracle::GetUnionType(result);
}

std::string BitFieldStructType::ToExplicitString() const {
  return "bitfield struct " + name();
}

const BitField& BitFieldStructType::LookupField(const std::string& name) const {
  for (const BitField& field : fields_) {
    if (field.name_and_type.name == name) {
      return field;
    }
  }
  ReportError("Couldn't find bitfield ", name);
}

void AggregateType::CheckForDuplicateFields() const {
  // Check the aggregate hierarchy and currently defined class for duplicate
  // field declarations.
  auto hierarchy = GetHierarchy();
  std::map<std::string, const AggregateType*> field_names;
  for (const AggregateType* aggregate_type : hierarchy) {
    for (const Field& field : aggregate_type->fields()) {
      const std::string& field_name = field.name_and_type.name;
      auto i = field_names.find(field_name);
      if (i != field_names.end()) {
        CurrentSourcePosition::Scope current_source_position(field.pos);
        std::string aggregate_type_name =
            aggregate_type->IsClassType() ? "class" : "struct";
        if (i->second == this) {
          ReportError(aggregate_type_name, " '", name(),
                      "' declares a field with the name '", field_name,
                      "' more than once");
        } else {
          ReportError(aggregate_type_name, " '", name(),
                      "' declares a field with the name '", field_name,
                      "' that masks an inherited field from class '",
                      i->second->name(), "'");
        }
      }
      field_names[field_name] = aggregate_type;
    }
  }
}

std::vector<const AggregateType*> AggregateType::GetHierarchy() const {
  if (!is_finalized_) Finalize();
  std::vector<const AggregateType*> hierarchy;
  const AggregateType* current_container_type = this;
  while (current_container_type != nullptr) {
    hierarchy.push_back(current_container_type);
    current_container_type =
        current_container_type->IsClassType()
            ? ClassType::cast(current_container_type)->GetSuperClass()
            : nullptr;
  }
  std::reverse(hierarchy.begin(), hierarchy.end());
  return hierarchy;
}

bool AggregateType::HasField(const std::string& name) const {
  if (!is_finalized_) Finalize();
  for (auto& field : fields_) {
    if (field.name_and_type.name == name) return true;
  }
  if (parent() != nullptr) {
    if (auto parent_class = ClassType::DynamicCast(parent())) {
      return parent_class->HasField(name);
    }
  }
  return false;
}

const Field& AggregateType::LookupFieldInternal(const std::string& name) const {
  for (auto& field : fields_) {
    if (field.name_and_type.name == name) return field;
  }
  if (parent() != nullptr) {
    if (auto parent_class = ClassType::DynamicCast(parent())) {
      return parent_class->LookupField(name);
    }
  }
  ReportError("no field ", name, " found in ", this->ToString());
}

const Field& AggregateType::LookupField(const std::string& name) const {
  if (!is_finalized_) Finalize();
  return LookupFieldInternal(name);
}

StructType::StructType(Namespace* nspace, const StructDeclaration* decl,
                       MaybeSpecializationKey specialized_from)
    : AggregateType(Kind::kStructType, nullptr, nspace, decl->name->value,
                    specialized_from),
      decl_(decl) {
  if (decl->flags & StructFlag::kExport) {
    generated_type_name_ = "TorqueStruct" + name();
  } else {
    generated_type_name_ =
        GlobalContext::MakeUniqueName("TorqueStruct" + SimpleName());
  }
}

std::string StructType::GetGeneratedTypeNameImpl() const {
  return generated_type_name_;
}

size_t StructType::PackedSize() const {
  size_t result = 0;
  for (const Field& field : fields()) {
    result += std::get<0>(field.GetFieldSizeInformation());
  }
  return result;
}

StructType::Classification StructType::ClassifyContents() const {
  Classification result = ClassificationFlag::kEmpty;
  for (const Field& struct_field : fields()) {
    const Type* field_type = struct_field.name_and_type.type;
    if (field_type->IsSubtypeOf(TypeOracle::GetStrongTaggedType())) {
      result |= ClassificationFlag::kStrongTagged;
    } else if (field_type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      result |= ClassificationFlag::kWeakTagged;
    } else if (auto field_as_struct = field_type->StructSupertype()) {
      result |= (*field_as_struct)->ClassifyContents();
    } else {
      result |= ClassificationFlag::kUntagged;
    }
  }
  return result;
}

// static
std::string Type::ComputeName(const std::string& basename,
                              MaybeSpecializationKey specialized_from) {
  if (!specialized_from) return basename;
  if (specialized_from->generic == TypeOracle::GetConstReferenceGeneric()) {
    return torque::ToString("const &", *specialized_from->specialized_types[0]);
  }
  if (specialized_from->generic == TypeOracle::GetMutableReferenceGeneric()) {
    return torque::ToString("&", *specialized_from->specialized_types[0]);
  }
  std::stringstream s;
  s << basename << "<";
  bool first = true;
  for (auto t : specialized_from->specialized_types) {
    if (!first) {
      s << ", ";
    }
    s << t->ToString();
    first = false;
  }
  s << ">";
  return s.str();
}

std::string StructType::SimpleNameImpl() const { return decl_->name->value; }

// static
std::optional<const Type*> Type::MatchUnaryGeneric(const Type* type,
                                                   GenericType* generic) {
  DCHECK_EQ(generic->generic_parameters().size(), 1);
  if (!type->GetSpecializedFrom()) {
    return std::nullopt;
  }
  auto& key = type->GetSpecializedFrom().value();
  if (key.generic != generic || key.specialized_types.size() != 1) {
    return std::nullopt;
  }
  return {key.specialized_types[0]};
}

std::vector<Method*> AggregateType::Methods(const std::string& name) const {
  if (!is_finalized_) Finalize();
  std::vector<Method*> result;
  std::copy_if(methods_.begin(), methods_.end(), std::back_inserter(result),
               [name](Macro* macro) { return macro->ReadableName() == name; });
  if (result.empty() && parent() != nullptr) {
    if (auto aggregate_parent = parent()->AggregateSupertype()) {
      return (*aggregate_parent)->Methods(name);
    }
  }
  return result;
}

std::string StructType::ToExplicitString() const { return "struct " + name(); }

void StructType::Finalize() const {
  if (is_finalized_) return;
  {
    CurrentScope::Scope scope_activator(nspace());
    CurrentSourcePosition::Scope position_activator(decl_->pos);
    TypeVisitor::VisitStructMethods(const_cast<StructType*>(this), decl_);
  }
  is_finalized_ = true;
  CheckForDuplicateFields();
}

ClassType::ClassType(const Type* parent, Namespace* nspace,
                     const std::string& name, ClassFlags flags,
                     const std::string& generates, const ClassDeclaration* decl,
                     const TypeAlias* alias)
    : AggregateType(Kind::kClassType, parent, nspace, name),
      size_(ResidueClass::Unknown()),
      flags_(flags),
      generates_(generates),
      decl_(decl),
      alias_(alias) {}

std::string ClassType::GetGeneratedTNodeTypeNameImpl() const {
  return generates_;
}

std::string ClassType::GetGeneratedTypeNameImpl() const {
  return IsConstexpr() ? GetGeneratedTNodeTypeName()
                       : "TNode<" + GetGeneratedTNodeTypeName() + ">";
}

std::string ClassType::ToExplicitString() const { return "class " + name(); }

bool ClassType::AllowInstantiation() const {
  return (!IsExtern() || nspace()->IsDefaultNamespace()) && !IsAbstract();
}

void ClassType::Finalize() const {
  if (is_finalized_) return;
  CurrentScope::Scope scope_activator(alias_->ParentScope());
  CurrentSourcePosition::Scope position_activator(decl_->pos);
  TypeVisitor::VisitClassFieldsAndMethods(const_cast<ClassType*>(this),
                                          this->decl_);
  is_finalized_ = true;
  CheckForDuplicateFields();
}

std::vector<Field> ClassType::ComputeAllFields() const {
  std::vector<Field> all_fields;
  const ClassType* super_class = this->GetSuperClass();
  if (super_class) {
    all_fields = super_class->ComputeAllFields();
  }
  const std::vector<Field>& fields = this->fields();
  all_fields.insert(all_fields.end(), fields.begin(), fields.end());
  return all_fields;
}

std::vector<Field> ClassType::ComputeHeaderFields() const {
  std::vector<Field> result;
  for (Field& field : ComputeAllFields()) {
    if (field.index) break;
    // The header is allowed to end with an optional padding field of size 0.
    DCHECK(std::get<0>(field.GetFieldSizeInformation()) == 0 ||
           *field.offset < header_size());
    result.push_back(std::move(field));
  }
  return result;
}

std::vector<Field> ClassType::ComputeArrayFields() const {
  std::vector<Field> result;
  for (Field& field : ComputeAllFields()) {
    if (!field.index) {
      // The header is allowed to end with an optional padding field of size 0.
      DCHECK(std::get<0>(field.GetFieldSizeInformation()) == 0 ||
             *field.offset < header_size());
      continue;
    }
    result.push_back(std::move(field));
  }
  return result;
}

void ClassType::InitializeInstanceTypes(
    std::optional<int> own, std::optional<std::pair<int, int>> range) const {
  DCHECK(!own_instance_type_.has_value());
  DCHECK(!instance_type_range_.has_value());
  own_instance_type_ = own;
  instance_type_range_ = range;
}

std::optional<int> ClassType::OwnInstanceType() const {
  DCHECK(GlobalContext::IsInstanceTypesInitialized());
  return own_instance_type_;
}

std::optional<std::pair<int, int>> ClassType::InstanceTypeRange() const {
  DCHECK(GlobalContext::IsInstanceTypesInitialized());
  return instance_type_range_;
}

namespace {
void ComputeSlotKindsHelper(std::vector<ObjectSlotKind>* slots,
                            size_t start_offset,
                            const std::vector<Field>& fields) {
  size_t offset = start_offset;
  for (const Field& field : fields) {
    size_t field_size = std::get<0>(field.GetFieldSizeInformation());
    // Support optional padding fields.
    if (field_size == 0) continue;
    size_t slot_index = offset / TargetArchitecture::TaggedSize();
    // Rounding-up division to find the number of slots occupied by all the
    // fields up to and including the current one.
    size_t used_slots =
        (offset + field_size + TargetArchitecture::TaggedSize() - 1) /
        TargetArchitecture::TaggedSize();
    while (used_slots > slots->size()) {
      slots->push_back(ObjectSlotKind::kNoPointer);
    }
    const Type* type = field.name_and_type.type;
    if (auto struct_type = type->StructSupertype()) {
      ComputeSlotKindsHelper(slots, offset, (*struct_type)->fields());
    } else {
      ObjectSlotKind kind;
      if (type->IsSubtypeOf(TypeOracle::GetObjectType())) {
        if (field.custom_weak_marking) {
          kind = ObjectSlotKind::kCustomWeakPointer;
        } else {
          kind = ObjectSlotKind::kStrongPointer;
        }
      } else if (type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
        DCHECK(!field.custom_weak_marking);
        kind = ObjectSlotKind::kMaybeObjectPointer;
      } else {
        kind = ObjectSlotKind::kNoPointer;
      }
      DCHECK(slots->at(slot_index) == ObjectSlotKind::kNoPointer);
      slots->at(slot_index) = kind;
    }

    offset += field_size;
  }
}
}  // namespace

std::vector<ObjectSlotKind> ClassType::ComputeHeaderSlotKinds() const {
  std::vector<ObjectSlotKind> result;
  std::vector<Field> header_fields = ComputeHeaderFields();
  ComputeSlotKindsHelper(&result, 0, header_fields);
  DCHECK_EQ(std::ceil(static_cast<double>(header_size()) /
                      TargetArchitecture::TaggedSize()),
            result.size());
  return result;
}

std::optional<ObjectSlotKind> ClassType::ComputeArraySlotKind() const {
  std::vector<ObjectSlotKind> kinds;
  ComputeSlotKindsHelper(&kinds, 0, ComputeArrayFields());
  if (kinds.empty()) return std::nullopt;
  std::sort(kinds.begin(), kinds.end());
  if (kinds.front() == kinds.back()) return {kinds.front()};
  if (kinds.front() == ObjectSlotKind::kStrongPointer &&
      kinds.back() == ObjectSlotKind::kMaybeObjectPointer) {
    return ObjectSlotKind::kMaybeObjectPointer;
  }
  Error("Array fields mix types with different GC visitation requirements.")
      .Throw();
}

bool ClassType::HasNoPointerSlotsExceptMap() const {
  const auto header_slot_kinds = ComputeHeaderSlotKinds();
  DCHECK_GE(header_slot_kinds.size(), 1);
  DCHECK_EQ(ComputeHeaderFields()[0].name_and_type.type,
            TypeOracle::GetMapType());
  for (size_t i = 1; i < header_slot_kinds.size(); ++i) {
    if (header_slot_kinds[i] != ObjectSlotKind::kNoPointer) return false;
  }
  if (auto slot = ComputeArraySlotKind()) {
    if (*slot != ObjectSlotKind::kNoPointer) return false;
  }
  return true;
}

bool ClassType::HasIndexedFieldsIncludingInParents() const {
  for (const auto& field : fields_) {
    if (field.index.has_value()) return true;
  }
  if (const ClassType* parent = GetSuperClass()) {
    return parent->HasIndexedFieldsIncludingInParents();
  }
  return false;
}

const Field* ClassType::GetFieldPreceding(size_t field_index) const {
  if (field_index > 0) {
    return &fields_[field_index - 1];
  }
  if (const ClassType* parent = GetSuperClass()) {
    return parent->GetFieldPreceding(parent->fields_.size());
  }
  return nullptr;
}

const ClassType* ClassType::GetClassDeclaringField(const Field& f) const {
  for (const Field& field : fields_) {
    if (f.name_and_type.name == field.name_and_type.name) return this;
  }
  return GetSuperClass()->GetClassDeclaringField(f);
}

std::string ClassType
### 提示词
```
这是目录为v8/src/torque/types.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/torque/types.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/torque/types.h"

#include <cmath>
#include <iostream>
#include <optional>

#include "src/base/bits.h"
#include "src/torque/ast.h"
#include "src/torque/declarable.h"
#include "src/torque/global-context.h"
#include "src/torque/source-positions.h"
#include "src/torque/type-oracle.h"
#include "src/torque/type-visitor.h"

namespace v8::internal::torque {

// This custom copy constructor doesn't copy aliases_ and id_ because they
// should be distinct for each type.
Type::Type(const Type& other) V8_NOEXCEPT
    : TypeBase(other),
      parent_(other.parent_),
      aliases_(),
      id_(TypeOracle::FreshTypeId()),
      constexpr_version_(other.constexpr_version_) {}
Type::Type(TypeBase::Kind kind, const Type* parent,
           MaybeSpecializationKey specialized_from)
    : TypeBase(kind),
      parent_(parent),
      id_(TypeOracle::FreshTypeId()),
      specialized_from_(specialized_from),
      constexpr_version_(nullptr) {}

std::string Type::ToString() const {
  if (aliases_.empty())
    return ComputeName(ToExplicitString(), GetSpecializedFrom());
  if (aliases_.size() == 1) return *aliases_.begin();
  std::stringstream result;
  int i = 0;
  for (const std::string& alias : aliases_) {
    if (i == 0) {
      result << alias << " (aka. ";
    } else if (i == 1) {
      result << alias;
    } else {
      result << ", " << alias;
    }
    ++i;
  }
  result << ")";
  return result.str();
}

std::string Type::SimpleName() const {
  if (aliases_.empty()) {
    std::stringstream result;
    result << SimpleNameImpl();
    if (GetSpecializedFrom()) {
      for (const Type* t : GetSpecializedFrom()->specialized_types) {
        result << "_" << t->SimpleName();
      }
    }
    return result.str();
  }
  return *aliases_.begin();
}

std::string Type::GetHandleTypeName(HandleKind kind,
                                    const std::string& type_name) const {
  switch (kind) {
    case HandleKind::kIndirect:
      return "Handle<" + type_name + ">";
    case HandleKind::kDirect:
      return "DirectHandle<" + type_name + ">";
  }
}

// TODO(danno): HandlifiedCppTypeName should be used universally in Torque
// where the C++ type of a Torque object is required.
std::string Type::HandlifiedCppTypeName(HandleKind kind) const {
  if (IsSubtypeOf(TypeOracle::GetSmiType())) return "int";
  if (IsSubtypeOf(TypeOracle::GetTaggedType())) {
    return GetHandleTypeName(kind, GetConstexprGeneratedTypeName());
  } else {
    return GetConstexprGeneratedTypeName();
  }
}

std::string Type::TagglifiedCppTypeName() const {
  if (IsSubtypeOf(TypeOracle::GetSmiType())) return "int";
  if (IsSubtypeOf(TypeOracle::GetTaggedType())) {
    return "Tagged<" + GetConstexprGeneratedTypeName() + ">";
  } else {
    return GetConstexprGeneratedTypeName();
  }
}

bool Type::IsSubtypeOf(const Type* supertype) const {
  if (supertype->IsTopType()) return true;
  if (IsNever()) return true;
  if (const UnionType* union_type = UnionType::DynamicCast(supertype)) {
    return union_type->IsSupertypeOf(this);
  }
  const Type* subtype = this;
  while (subtype != nullptr) {
    if (subtype == supertype) return true;
    subtype = subtype->parent();
  }
  return false;
}

std::string Type::GetConstexprGeneratedTypeName() const {
  const Type* constexpr_version = ConstexprVersion();
  if (constexpr_version == nullptr) {
    Error("Type '", ToString(), "' requires a constexpr representation");
    return "";
  }
  return constexpr_version->GetGeneratedTypeName();
}

std::optional<const ClassType*> Type::ClassSupertype() const {
  for (const Type* t = this; t != nullptr; t = t->parent()) {
    if (auto* class_type = ClassType::DynamicCast(t)) {
      return class_type;
    }
  }
  return std::nullopt;
}

std::optional<const StructType*> Type::StructSupertype() const {
  for (const Type* t = this; t != nullptr; t = t->parent()) {
    if (auto* struct_type = StructType::DynamicCast(t)) {
      return struct_type;
    }
  }
  return std::nullopt;
}

std::optional<const AggregateType*> Type::AggregateSupertype() const {
  for (const Type* t = this; t != nullptr; t = t->parent()) {
    if (auto* aggregate_type = AggregateType::DynamicCast(t)) {
      return aggregate_type;
    }
  }
  return std::nullopt;
}

// static
const Type* Type::CommonSupertype(const Type* a, const Type* b) {
  int diff = a->Depth() - b->Depth();
  const Type* a_supertype = a;
  const Type* b_supertype = b;
  for (; diff > 0; --diff) a_supertype = a_supertype->parent();
  for (; diff < 0; ++diff) b_supertype = b_supertype->parent();
  while (a_supertype && b_supertype) {
    if (a_supertype == b_supertype) return a_supertype;
    a_supertype = a_supertype->parent();
    b_supertype = b_supertype->parent();
  }
  ReportError("types " + a->ToString() + " and " + b->ToString() +
              " have no common supertype");
}

int Type::Depth() const {
  int result = 0;
  for (const Type* current = parent_; current; current = current->parent_) {
    ++result;
  }
  return result;
}

bool Type::IsAbstractName(const std::string& name) const {
  if (!IsAbstractType()) return false;
  return AbstractType::cast(this)->name() == name;
}

std::string Type::GetGeneratedTypeName() const {
  std::string result = GetGeneratedTypeNameImpl();
  if (result.empty() || result == "TNode<>") {
    ReportError("Generated type is required for type '", ToString(),
                "'. Use 'generates' clause in definition.");
  }
  return result;
}

std::string Type::GetGeneratedTNodeTypeName() const {
  std::string result = GetGeneratedTNodeTypeNameImpl();
  if (result.empty() || IsConstexpr()) {
    ReportError("Generated TNode type is required for type '", ToString(),
                "'. Use 'generates' clause in definition.");
  }
  return result;
}

std::string AbstractType::GetGeneratedTypeNameImpl() const {
  // A special case that is not very well represented by the "generates"
  // syntax in the .tq files: Lazy<T> represents a std::function that
  // produces a TNode of the wrapped type.
  if (std::optional<const Type*> type_wrapped_in_lazy =
          Type::MatchUnaryGeneric(this, TypeOracle::GetLazyGeneric())) {
    DCHECK(!IsConstexpr());
    return "std::function<" + (*type_wrapped_in_lazy)->GetGeneratedTypeName() +
           "()>";
  }

  if (generated_type_.empty()) {
    return parent()->GetGeneratedTypeName();
  }
  return IsConstexpr() ? generated_type_ : "TNode<" + generated_type_ + ">";
}

std::string AbstractType::GetGeneratedTNodeTypeNameImpl() const {
  if (generated_type_.empty()) return parent()->GetGeneratedTNodeTypeName();
  return generated_type_;
}

std::vector<TypeChecker> AbstractType::GetTypeCheckers() const {
  if (UseParentTypeChecker()) return parent()->GetTypeCheckers();
  std::string type_name = name();
  if (auto strong_type =
          Type::MatchUnaryGeneric(this, TypeOracle::GetWeakGeneric())) {
    auto strong_runtime_types = (*strong_type)->GetTypeCheckers();
    std::vector<TypeChecker> result;
    for (const TypeChecker& type : strong_runtime_types) {
      // Generic parameter in Weak<T> should have already been checked to
      // extend HeapObject, so it couldn't itself be another weak type.
      DCHECK(type.weak_ref_to.empty());
      result.push_back({type_name, type.type});
    }
    return result;
  }
  return {{type_name, ""}};
}

std::string BuiltinPointerType::ToExplicitString() const {
  std::stringstream result;
  result << "builtin (";
  PrintCommaSeparatedList(result, parameter_types_);
  result << ") => " << *return_type_;
  return result.str();
}

std::string BuiltinPointerType::SimpleNameImpl() const {
  std::stringstream result;
  result << "BuiltinPointer";
  for (const Type* t : parameter_types_) {
    result << "_" << t->SimpleName();
  }
  result << "_" << return_type_->SimpleName();
  return result.str();
}

std::string UnionType::ToExplicitString() const {
  std::stringstream result;
  result << "(";
  bool first = true;
  for (const Type* t : types_) {
    if (!first) {
      result << " | ";
    }
    first = false;
    result << *t;
  }
  result << ")";
  return result.str();
}

std::string UnionType::SimpleNameImpl() const {
  std::stringstream result;
  bool first = true;
  for (const Type* t : types_) {
    if (!first) {
      result << "_OR_";
    }
    first = false;
    result << t->SimpleName();
  }
  return result.str();
}

std::string UnionType::GetGeneratedTNodeTypeNameImpl() const {
  if (types_.size() <= 3) {
    std::set<std::string> members;
    for (const Type* t : types_) {
      members.insert(t->GetGeneratedTNodeTypeName());
    }
    if (members == std::set<std::string>{"Smi", "HeapNumber"}) {
      return "Number";
    }
    if (members == std::set<std::string>{"Smi", "HeapNumber", "BigInt"}) {
      return "Numeric";
    }
  }
  return parent()->GetGeneratedTNodeTypeName();
}

std::string UnionType::GetRuntimeType() const {
  for (const Type* t : types_) {
    if (!t->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      return parent()->GetRuntimeType();
    }
  }
  return "Tagged<" + GetConstexprGeneratedTypeName() + ">";
}

// static
void UnionType::InsertConstexprGeneratedTypeName(std::set<std::string>& names,
                                                 const Type* t) {
  if (t->IsUnionType()) {
    for (const Type* u : ((const UnionType*)t)->types_) {
      names.insert(u->GetConstexprGeneratedTypeName());
    }
  } else {
    names.insert(t->GetConstexprGeneratedTypeName());
  }
}

std::string UnionType::GetConstexprGeneratedTypeName() const {
  // For non-tagged unions, use the superclass GetConstexprGeneratedTypeName.
  for (const Type* t : types_) {
    if (!t->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      return this->Type::GetConstexprGeneratedTypeName();
    }
  }

  // Allow some aliased simple names to be used as-is.
  std::string simple_name = SimpleName();
  if (simple_name == "Object") return simple_name;
  if (simple_name == "Number") return simple_name;
  if (simple_name == "Numeric") return simple_name;
  if (simple_name == "JSAny") return simple_name;
  if (simple_name == "JSPrimitive") return simple_name;

  // Deduplicate generated typenames and flatten unions.
  std::set<std::string> names;
  for (const Type* t : types_) {
    InsertConstexprGeneratedTypeName(names, t);
  }
  std::stringstream result;
  result << "Union<";
  bool first = true;
  for (std::string name : names) {
    if (!first) {
      result << ", ";
    }
    first = false;
    result << name;
  }
  result << ">";
  return result.str();
}

std::string UnionType::GetDebugType() const { return parent()->GetDebugType(); }

void UnionType::RecomputeParent() {
  const Type* parent = nullptr;
  for (const Type* t : types_) {
    if (parent == nullptr) {
      parent = t;
    } else {
      parent = CommonSupertype(parent, t);
    }
  }
  set_parent(parent);
}

void UnionType::Subtract(const Type* t) {
  for (auto it = types_.begin(); it != types_.end();) {
    if ((*it)->IsSubtypeOf(t)) {
      it = types_.erase(it);
    } else {
      ++it;
    }
  }
  if (types_.empty()) types_.insert(TypeOracle::GetNeverType());
  RecomputeParent();
}

const Type* SubtractType(const Type* a, const Type* b) {
  UnionType result = UnionType::FromType(a);
  result.Subtract(b);
  return TypeOracle::GetUnionType(result);
}

std::string BitFieldStructType::ToExplicitString() const {
  return "bitfield struct " + name();
}

const BitField& BitFieldStructType::LookupField(const std::string& name) const {
  for (const BitField& field : fields_) {
    if (field.name_and_type.name == name) {
      return field;
    }
  }
  ReportError("Couldn't find bitfield ", name);
}

void AggregateType::CheckForDuplicateFields() const {
  // Check the aggregate hierarchy and currently defined class for duplicate
  // field declarations.
  auto hierarchy = GetHierarchy();
  std::map<std::string, const AggregateType*> field_names;
  for (const AggregateType* aggregate_type : hierarchy) {
    for (const Field& field : aggregate_type->fields()) {
      const std::string& field_name = field.name_and_type.name;
      auto i = field_names.find(field_name);
      if (i != field_names.end()) {
        CurrentSourcePosition::Scope current_source_position(field.pos);
        std::string aggregate_type_name =
            aggregate_type->IsClassType() ? "class" : "struct";
        if (i->second == this) {
          ReportError(aggregate_type_name, " '", name(),
                      "' declares a field with the name '", field_name,
                      "' more than once");
        } else {
          ReportError(aggregate_type_name, " '", name(),
                      "' declares a field with the name '", field_name,
                      "' that masks an inherited field from class '",
                      i->second->name(), "'");
        }
      }
      field_names[field_name] = aggregate_type;
    }
  }
}

std::vector<const AggregateType*> AggregateType::GetHierarchy() const {
  if (!is_finalized_) Finalize();
  std::vector<const AggregateType*> hierarchy;
  const AggregateType* current_container_type = this;
  while (current_container_type != nullptr) {
    hierarchy.push_back(current_container_type);
    current_container_type =
        current_container_type->IsClassType()
            ? ClassType::cast(current_container_type)->GetSuperClass()
            : nullptr;
  }
  std::reverse(hierarchy.begin(), hierarchy.end());
  return hierarchy;
}

bool AggregateType::HasField(const std::string& name) const {
  if (!is_finalized_) Finalize();
  for (auto& field : fields_) {
    if (field.name_and_type.name == name) return true;
  }
  if (parent() != nullptr) {
    if (auto parent_class = ClassType::DynamicCast(parent())) {
      return parent_class->HasField(name);
    }
  }
  return false;
}

const Field& AggregateType::LookupFieldInternal(const std::string& name) const {
  for (auto& field : fields_) {
    if (field.name_and_type.name == name) return field;
  }
  if (parent() != nullptr) {
    if (auto parent_class = ClassType::DynamicCast(parent())) {
      return parent_class->LookupField(name);
    }
  }
  ReportError("no field ", name, " found in ", this->ToString());
}

const Field& AggregateType::LookupField(const std::string& name) const {
  if (!is_finalized_) Finalize();
  return LookupFieldInternal(name);
}

StructType::StructType(Namespace* nspace, const StructDeclaration* decl,
                       MaybeSpecializationKey specialized_from)
    : AggregateType(Kind::kStructType, nullptr, nspace, decl->name->value,
                    specialized_from),
      decl_(decl) {
  if (decl->flags & StructFlag::kExport) {
    generated_type_name_ = "TorqueStruct" + name();
  } else {
    generated_type_name_ =
        GlobalContext::MakeUniqueName("TorqueStruct" + SimpleName());
  }
}

std::string StructType::GetGeneratedTypeNameImpl() const {
  return generated_type_name_;
}

size_t StructType::PackedSize() const {
  size_t result = 0;
  for (const Field& field : fields()) {
    result += std::get<0>(field.GetFieldSizeInformation());
  }
  return result;
}

StructType::Classification StructType::ClassifyContents() const {
  Classification result = ClassificationFlag::kEmpty;
  for (const Field& struct_field : fields()) {
    const Type* field_type = struct_field.name_and_type.type;
    if (field_type->IsSubtypeOf(TypeOracle::GetStrongTaggedType())) {
      result |= ClassificationFlag::kStrongTagged;
    } else if (field_type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
      result |= ClassificationFlag::kWeakTagged;
    } else if (auto field_as_struct = field_type->StructSupertype()) {
      result |= (*field_as_struct)->ClassifyContents();
    } else {
      result |= ClassificationFlag::kUntagged;
    }
  }
  return result;
}

// static
std::string Type::ComputeName(const std::string& basename,
                              MaybeSpecializationKey specialized_from) {
  if (!specialized_from) return basename;
  if (specialized_from->generic == TypeOracle::GetConstReferenceGeneric()) {
    return torque::ToString("const &", *specialized_from->specialized_types[0]);
  }
  if (specialized_from->generic == TypeOracle::GetMutableReferenceGeneric()) {
    return torque::ToString("&", *specialized_from->specialized_types[0]);
  }
  std::stringstream s;
  s << basename << "<";
  bool first = true;
  for (auto t : specialized_from->specialized_types) {
    if (!first) {
      s << ", ";
    }
    s << t->ToString();
    first = false;
  }
  s << ">";
  return s.str();
}

std::string StructType::SimpleNameImpl() const { return decl_->name->value; }

// static
std::optional<const Type*> Type::MatchUnaryGeneric(const Type* type,
                                                   GenericType* generic) {
  DCHECK_EQ(generic->generic_parameters().size(), 1);
  if (!type->GetSpecializedFrom()) {
    return std::nullopt;
  }
  auto& key = type->GetSpecializedFrom().value();
  if (key.generic != generic || key.specialized_types.size() != 1) {
    return std::nullopt;
  }
  return {key.specialized_types[0]};
}

std::vector<Method*> AggregateType::Methods(const std::string& name) const {
  if (!is_finalized_) Finalize();
  std::vector<Method*> result;
  std::copy_if(methods_.begin(), methods_.end(), std::back_inserter(result),
               [name](Macro* macro) { return macro->ReadableName() == name; });
  if (result.empty() && parent() != nullptr) {
    if (auto aggregate_parent = parent()->AggregateSupertype()) {
      return (*aggregate_parent)->Methods(name);
    }
  }
  return result;
}

std::string StructType::ToExplicitString() const { return "struct " + name(); }

void StructType::Finalize() const {
  if (is_finalized_) return;
  {
    CurrentScope::Scope scope_activator(nspace());
    CurrentSourcePosition::Scope position_activator(decl_->pos);
    TypeVisitor::VisitStructMethods(const_cast<StructType*>(this), decl_);
  }
  is_finalized_ = true;
  CheckForDuplicateFields();
}

ClassType::ClassType(const Type* parent, Namespace* nspace,
                     const std::string& name, ClassFlags flags,
                     const std::string& generates, const ClassDeclaration* decl,
                     const TypeAlias* alias)
    : AggregateType(Kind::kClassType, parent, nspace, name),
      size_(ResidueClass::Unknown()),
      flags_(flags),
      generates_(generates),
      decl_(decl),
      alias_(alias) {}

std::string ClassType::GetGeneratedTNodeTypeNameImpl() const {
  return generates_;
}

std::string ClassType::GetGeneratedTypeNameImpl() const {
  return IsConstexpr() ? GetGeneratedTNodeTypeName()
                       : "TNode<" + GetGeneratedTNodeTypeName() + ">";
}

std::string ClassType::ToExplicitString() const { return "class " + name(); }

bool ClassType::AllowInstantiation() const {
  return (!IsExtern() || nspace()->IsDefaultNamespace()) && !IsAbstract();
}

void ClassType::Finalize() const {
  if (is_finalized_) return;
  CurrentScope::Scope scope_activator(alias_->ParentScope());
  CurrentSourcePosition::Scope position_activator(decl_->pos);
  TypeVisitor::VisitClassFieldsAndMethods(const_cast<ClassType*>(this),
                                          this->decl_);
  is_finalized_ = true;
  CheckForDuplicateFields();
}

std::vector<Field> ClassType::ComputeAllFields() const {
  std::vector<Field> all_fields;
  const ClassType* super_class = this->GetSuperClass();
  if (super_class) {
    all_fields = super_class->ComputeAllFields();
  }
  const std::vector<Field>& fields = this->fields();
  all_fields.insert(all_fields.end(), fields.begin(), fields.end());
  return all_fields;
}

std::vector<Field> ClassType::ComputeHeaderFields() const {
  std::vector<Field> result;
  for (Field& field : ComputeAllFields()) {
    if (field.index) break;
    // The header is allowed to end with an optional padding field of size 0.
    DCHECK(std::get<0>(field.GetFieldSizeInformation()) == 0 ||
           *field.offset < header_size());
    result.push_back(std::move(field));
  }
  return result;
}

std::vector<Field> ClassType::ComputeArrayFields() const {
  std::vector<Field> result;
  for (Field& field : ComputeAllFields()) {
    if (!field.index) {
      // The header is allowed to end with an optional padding field of size 0.
      DCHECK(std::get<0>(field.GetFieldSizeInformation()) == 0 ||
             *field.offset < header_size());
      continue;
    }
    result.push_back(std::move(field));
  }
  return result;
}

void ClassType::InitializeInstanceTypes(
    std::optional<int> own, std::optional<std::pair<int, int>> range) const {
  DCHECK(!own_instance_type_.has_value());
  DCHECK(!instance_type_range_.has_value());
  own_instance_type_ = own;
  instance_type_range_ = range;
}

std::optional<int> ClassType::OwnInstanceType() const {
  DCHECK(GlobalContext::IsInstanceTypesInitialized());
  return own_instance_type_;
}

std::optional<std::pair<int, int>> ClassType::InstanceTypeRange() const {
  DCHECK(GlobalContext::IsInstanceTypesInitialized());
  return instance_type_range_;
}

namespace {
void ComputeSlotKindsHelper(std::vector<ObjectSlotKind>* slots,
                            size_t start_offset,
                            const std::vector<Field>& fields) {
  size_t offset = start_offset;
  for (const Field& field : fields) {
    size_t field_size = std::get<0>(field.GetFieldSizeInformation());
    // Support optional padding fields.
    if (field_size == 0) continue;
    size_t slot_index = offset / TargetArchitecture::TaggedSize();
    // Rounding-up division to find the number of slots occupied by all the
    // fields up to and including the current one.
    size_t used_slots =
        (offset + field_size + TargetArchitecture::TaggedSize() - 1) /
        TargetArchitecture::TaggedSize();
    while (used_slots > slots->size()) {
      slots->push_back(ObjectSlotKind::kNoPointer);
    }
    const Type* type = field.name_and_type.type;
    if (auto struct_type = type->StructSupertype()) {
      ComputeSlotKindsHelper(slots, offset, (*struct_type)->fields());
    } else {
      ObjectSlotKind kind;
      if (type->IsSubtypeOf(TypeOracle::GetObjectType())) {
        if (field.custom_weak_marking) {
          kind = ObjectSlotKind::kCustomWeakPointer;
        } else {
          kind = ObjectSlotKind::kStrongPointer;
        }
      } else if (type->IsSubtypeOf(TypeOracle::GetTaggedType())) {
        DCHECK(!field.custom_weak_marking);
        kind = ObjectSlotKind::kMaybeObjectPointer;
      } else {
        kind = ObjectSlotKind::kNoPointer;
      }
      DCHECK(slots->at(slot_index) == ObjectSlotKind::kNoPointer);
      slots->at(slot_index) = kind;
    }

    offset += field_size;
  }
}
}  // namespace

std::vector<ObjectSlotKind> ClassType::ComputeHeaderSlotKinds() const {
  std::vector<ObjectSlotKind> result;
  std::vector<Field> header_fields = ComputeHeaderFields();
  ComputeSlotKindsHelper(&result, 0, header_fields);
  DCHECK_EQ(std::ceil(static_cast<double>(header_size()) /
                      TargetArchitecture::TaggedSize()),
            result.size());
  return result;
}

std::optional<ObjectSlotKind> ClassType::ComputeArraySlotKind() const {
  std::vector<ObjectSlotKind> kinds;
  ComputeSlotKindsHelper(&kinds, 0, ComputeArrayFields());
  if (kinds.empty()) return std::nullopt;
  std::sort(kinds.begin(), kinds.end());
  if (kinds.front() == kinds.back()) return {kinds.front()};
  if (kinds.front() == ObjectSlotKind::kStrongPointer &&
      kinds.back() == ObjectSlotKind::kMaybeObjectPointer) {
    return ObjectSlotKind::kMaybeObjectPointer;
  }
  Error("Array fields mix types with different GC visitation requirements.")
      .Throw();
}

bool ClassType::HasNoPointerSlotsExceptMap() const {
  const auto header_slot_kinds = ComputeHeaderSlotKinds();
  DCHECK_GE(header_slot_kinds.size(), 1);
  DCHECK_EQ(ComputeHeaderFields()[0].name_and_type.type,
            TypeOracle::GetMapType());
  for (size_t i = 1; i < header_slot_kinds.size(); ++i) {
    if (header_slot_kinds[i] != ObjectSlotKind::kNoPointer) return false;
  }
  if (auto slot = ComputeArraySlotKind()) {
    if (*slot != ObjectSlotKind::kNoPointer) return false;
  }
  return true;
}

bool ClassType::HasIndexedFieldsIncludingInParents() const {
  for (const auto& field : fields_) {
    if (field.index.has_value()) return true;
  }
  if (const ClassType* parent = GetSuperClass()) {
    return parent->HasIndexedFieldsIncludingInParents();
  }
  return false;
}

const Field* ClassType::GetFieldPreceding(size_t field_index) const {
  if (field_index > 0) {
    return &fields_[field_index - 1];
  }
  if (const ClassType* parent = GetSuperClass()) {
    return parent->GetFieldPreceding(parent->fields_.size());
  }
  return nullptr;
}

const ClassType* ClassType::GetClassDeclaringField(const Field& f) const {
  for (const Field& field : fields_) {
    if (f.name_and_type.name == field.name_and_type.name) return this;
  }
  return GetSuperClass()->GetClassDeclaringField(f);
}

std::string ClassType::GetSliceMacroName(const Field& field) const {
  const ClassType* declarer = GetClassDeclaringField(field);
  return "FieldSlice" + declarer->name() +
         CamelifyString(field.name_and_type.name);
}

void ClassType::GenerateAccessors() {
  bool at_or_after_indexed_field = false;
  if (const ClassType* parent = GetSuperClass()) {
    at_or_after_indexed_field = parent->HasIndexedFieldsIncludingInParents();
  }
  // For each field, construct AST snippets that implement a CSA accessor
  // function. The implementation iterator will turn the snippets into code.
  for (size_t field_index = 0; field_index < fields_.size(); ++field_index) {
    Field& field = fields_[field_index];
    if (field.name_and_type.type == TypeOracle::GetVoidType()) {
      continue;
    }
    at_or_after_indexed_field =
        at_or_after_indexed_field || field.index.has_value();
    CurrentSourcePosition::Scope position_activator(field.pos);

    IdentifierExpression* parameter = MakeIdentifierExpression("o");
    IdentifierExpression* index = MakeIdentifierExpression("i");

    std::string camel_field_name = CamelifyString(field.name_and_type.name);

    if (at_or_after_indexed_field) {
      if (!field.index.has_value()) {
        // There's no fundamental reason we couldn't generate functions to get
        // references instead of slices, but it's not yet implemented.
        ReportError(
            "Torque doesn't yet support non-indexed fields after indexed "
            "fields");
      }

      GenerateSliceAccessor(field_index);
    }

    // For now, only generate indexed accessors for simple types
    if (field.index.has_value() && field.name_and_type.type->IsStructType()) {
      continue;
    }

    // An explicit index is only used for indexed fields not marked as optional.
    // Optional fields implicitly load or store item zero.
    bool use_index = field.index && !field.index->optional;

    // Load accessor
    std::string load_macro_name = "Load" + this->name() + camel_field_name;
    Signature load_signature;
    load_signature.parameter_names.push_back(MakeNode<Identifier>("o"));
    load_signature.parameter_types.types.push_back(this);
    if (use_index) {
      load_signature.parameter_names.push_back(MakeNode<Identifier>("i"));
      load_signature.parameter_types.types.push_back(
          TypeOracle::GetIntPtrType());
    }
    load_signature.parameter_types.var_args = false;
    load_signature.return_type = field.name_and_type.type;

    Expression* load_expression =
        MakeFieldAccessExpression(parameter, field.name_and_type.name);
    if (use_index) {
      load_expression =
          MakeNode<ElementAccessExpression>(load_expression, index);
    }
    Statement* load_body = MakeNode<ReturnStatement>(load_expression);
    Declarations::DeclareMacro(load_macro_name, true, std::nullopt,
                               load_signature, load_body, std::nullopt);

    // Store accessor
    if (!field.const_qualified) {
      IdentifierExpression* value = MakeIdentifierExpression("v");
      std::string store_macro_name = "Store" + this->name() + camel_field_name;
      Signature store_signature;
      store_signature.parameter_names.push_back(MakeNode<Identifier>("o"));
      store_signature.parameter_types.types.push_back(this);
      if (use_index) {
        store_signature.parameter_names.push_back(MakeNode<Identifier>("i"));
        store_signature.parameter_types.types.push_back(
            TypeOracle::GetIntPtrType());
      }
      store_signature.parameter_names.push_back(MakeNode<Identifier>("v"));
      store_signature.parameter_types.types.push_back(field.name_and_type.type);
      store_signature.parameter_types.var_args = false;
      // TODO(danno): Store macros probably should return their value argument
      store_signature.return_type = TypeOracle::GetVoidType();
      Expression* store_expression =
          MakeFieldAccessExpression(parameter, field.name_and_type.name);
      if (use_index) {
        store_expression =
            MakeNode<ElementAccessExpression>(store_expression, index);
      }
      Statement* store_body = MakeNode<ExpressionStatement>(
          MakeNode<AssignmentExpression>(store_expression, value));
      Declarations::DeclareMacro(store_macro_name, true, std::nullopt,
                                 store_signature, store_body, std::nullopt,
                                 false);
    }
  }
}

void ClassType::GenerateSliceAccessor(size_t field_index) {
  // Generate a Torque macro for getting a Slice to this field. This macro can
  // be called by the dot operator for this field. In Torque, this function for
  // class "ClassName" and field "field_name" and field type "FieldType" would
  // be written as one of the following:
  //
  // If the field has a known offset (in this example, 16):
  // FieldSliceClassNameFieldName(o: ClassName) {
  //   return torque_internal::unsafe::New{Const,Mutable}Slice<FieldType>(
  //     /*object:*/ o,
  //     /*offset:*/ 16,
  //     /*length:*/ torque_internal::%IndexedFieldLength<ClassName>(
  //                     o, "field_name")
  //   );
  // }
  //
  // If the field has an unknown offset, and the previous field is named p, is
  // not const, and is of type PType with size 4:
  // FieldSliceClassNameFieldName(o: ClassName) {
  //   const previous = %FieldSlice<ClassName, MutableSlice<PType>>(o, "p");
  //   return torque_internal::unsafe::New{Const,Mutable}Slice<FieldType>(
  //     /*object:*/ o,
  //     /*offset:*/ previous.offset + 4 * previous.length,
  //     /*length:*/ torque_internal::%IndexedFieldLength<ClassName>(
  //                     o, "field_name")
  //   );
  // }
  const Field& field = fields_[field_index];
  std::string macro_name = GetSliceMacroName(field);
  Signature signature;
  Identifier* parameter_identifier = MakeNode<Identifier>("o");
  signature.parameter_names.push_back(parameter_identifier);
  signature.parameter_types.types.push_back(this);
  signature.parameter_types.var_args = false;
  signature.return_type =
      field.const_qualified
          ? TypeOracle::GetConstSliceType(field.name_and_type.type)
          : TypeOracle::GetMutableSliceType(field.name_and_type.type);

  std::vector<Statement*> statements;
  Expression* offset_expression = nullptr;
  IdentifierExpression* parameter =
      MakeNode<IdentifierExpression>(parameter_identifier);

  if (field.offset.has_value()) {
    offset_expression =
        MakeNode<IntegerLiteralExpression>(IntegerLiteral(*field.offset));
  } else {
    const Field* previous = GetFieldPreceding(field_index);
    DCHECK_NOT_NULL(previous);

    const Type* previous_slice_type =
        previous->const_qualified
            ? TypeOracle::GetConstSliceType(previous->name_and_type.type)
            : TypeOracle::GetMutableSliceType(previous->name_and_type.type);

    // %FieldSlice<ClassName, MutableSlice<PType>>(o, "p")
    Expression* previous_expression = MakeCallExpression(
        MakeIdentifierExpression(
            {"torque_internal"}, "%FieldSlice",
            {MakeNode<PrecomputedTypeExpression>(this),
             MakeNode<PrecomputedTypeExpression>(previous_slice_type)}),
        {parameter, MakeNode<StringLiteralExpression>(
                        StringLiteralQuote(previous->name_and_type.name))});

    // const previous = %FieldSlice<ClassName, MutableSlice<PType>>(o, "p");
    Statement* define_previous =
        MakeConstDeclarationStatement("previous", previous_expression);
    statements.push_back(define_previous);

    // 4
    size_t previous_element_size;
```