Response: My thought process to summarize the C++ code and relate it to JavaScript:

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and, if applicable, a JavaScript example demonstrating the connection. The file path `v8/src/compiler/representation-change.cc` immediately suggests this code is about how V8 handles different data types internally during compilation.

2. **Initial Skim for Keywords:** I quickly scanned the code for recurring keywords and concepts. Terms like `Truncation`, `Representation`, `MachineRepresentation`, `Tagged`, `Float64`, `Word32`, `BigInt`, `TypeCheck`, and function names like `GetRepresentationFor` and `InsertConversion` stood out. This gave me a high-level idea that the code is about converting between different ways data can be represented.

3. **Focus on the `Truncation` Class:** The `Truncation` class appears early and defines different kinds of truncations (like `kBool`, `kWord32`, `kWord64`). The associated static methods (`Generalize`, `LessGeneral`) suggest it's about establishing relationships and compatibilities between these truncations. This likely relates to how V8 optimizes code by potentially reducing the precision of numbers when it's safe to do so.

4. **Analyze `RepresentationChanger` Class:** This class seems to be the core of the file. The constructor takes `JSGraph`, `JSHeapBroker`, and `SimplifiedLoweringVerifier`, which are all components of the V8 compiler. The central method `GetRepresentationFor` strongly hints at the class's purpose: to ensure a value is in the correct representation needed by its usage.

5. **Break Down `GetRepresentationFor`:** I looked at the logic within `GetRepresentationFor`. It checks for no-ops, handles BigInts specially, and then has a `switch` statement based on the `use_info.representation()`. This confirms that the code dispatches to different conversion logic depending on the desired target representation.

6. **Examine Specific Representation Functions:** I glanced at functions like `GetTaggedSignedRepresentationFor`, `GetTaggedPointerRepresentationFor`, `GetFloat64RepresentationFor`, and `GetWord32RepresentationFor`. These functions contain logic to convert from various source representations to the target representation, often using `InsertConversion` with specific operators (like `simplified()->ChangeInt32ToTagged()` or `machine()->ChangeInt32ToFloat64()`). This solidified the idea that the code is about *explicitly* managing data type conversions.

7. **Identify the Connection to JavaScript:** JavaScript is dynamically typed, but V8 needs to optimize it. The representation changes are about how V8 *internally* handles JavaScript's flexible types. For example, a JavaScript number might be represented as an integer, a floating-point number, or even a tagged pointer internally. The `representation-change.cc` file deals with the transitions between these internal representations.

8. **Formulate the Summary:** Based on the above analysis, I formulated the summary:
    * The file manages the conversion of data between different internal representations used by V8 during compilation.
    * It defines a hierarchy of "truncations" to track the precision and allowed operations on values.
    * The `RepresentationChanger` class and its `GetRepresentationFor` method are central to this process, ensuring values have the correct representation for their uses.

9. **Create a JavaScript Example:**  To illustrate the connection, I thought about scenarios where JavaScript numbers might have different internal representations. Simple arithmetic with small integers likely uses optimized integer representations. Operations involving floating-point numbers or large numbers would use different representations. Type coercion (e.g., using `+` with a string and a number) forces V8 to change representations. Therefore, I chose examples showing:
    * Basic integer addition (likely using optimized integer representation).
    * Addition involving a floating-point number (requiring conversion to a floating-point representation).
    * Concatenation with a number (requiring conversion to a string representation, which is a tagged pointer in V8).

10. **Refine and Review:** I reviewed the summary and the JavaScript examples to ensure they were clear, concise, and accurately reflected the code's purpose. I made sure the JavaScript examples demonstrated different kinds of internal representation shifts that the C++ code would be responsible for managing.
## 功能归纳：

这个C++源代码文件 `representation-change.cc` 的主要功能是**管理和执行V8 JavaScript引擎在编译过程中值表示形式的转换**。

更具体地说，它负责：

* **定义和管理值的内部表示形式 (Representation)：**  V8在内部使用多种表示形式来存储JavaScript值，例如 `kTaggedSigned` (小整数)，`kTaggedPointer` (堆对象指针)，`kFloat64` (双精度浮点数)，`kWord32` (32位整数) 等。这个文件处理在不同表示形式之间的转换。
* **定义“截断 (Truncation)”的概念：**  `Truncation` 类描述了对值的使用方式，例如是否需要将其截断为布尔值、32位整数或64位整数。这有助于优化转换过程，避免不必要的精度损失。
* **提供 `RepresentationChanger` 类：** 这个类是核心，包含了执行表示形式转换的逻辑。它会根据值的当前表示形式、目标表示形式和使用方式（通过 `UseInfo` 传递）来插入必要的转换操作。
* **插入显式的转换操作：** 当需要将一个值从一种表示形式转换为另一种表示形式时，`RepresentationChanger` 会在编译后的代码中插入相应的机器指令或简化操作，例如 `ChangeInt32ToTaggedSigned`，`ChangeFloat64ToInt32` 等。
* **处理类型检查和优化：**  转换过程中会考虑值的类型信息，并进行相应的类型检查。例如，在将一个Tagged值转换为Signed时，可能会插入 `CheckedTaggedToTaggedSigned` 操作来确保值实际上是一个小整数。
* **支持不同的数值类型：**  该文件处理包括整数、浮点数、布尔值以及BigInt等不同JavaScript数值类型的表示形式转换。

**简而言之，`representation-change.cc` 是 V8 编译器中负责数据类型转换的关键组件，它确保JavaScript的值在编译后的代码中以合适的内部表示形式被使用，并进行必要的类型检查和优化。**

## 与JavaScript功能的关联和JavaScript示例：

虽然这个文件是C++代码，属于V8引擎的内部实现，但它直接影响着JavaScript代码的执行效率和行为。  JavaScript是一门动态类型语言，变量的类型在运行时可以改变。V8需要在编译时和运行时处理这种灵活性，而表示形式转换就是其中的一个重要环节。

以下是一些JavaScript示例，展示了在底层可能触发 `representation-change.cc` 中代码执行的情况：

**1. 数字类型的转换：**

```javascript
let x = 10; // 可能是 kTaggedSigned
let y = 3.14; // 可能是 kFloat64

let sum = x + y; // V8可能需要将 x 从 kTaggedSigned 转换为 kFloat64 才能进行加法运算
```

在这个例子中，整数 `x` 和浮点数 `y` 相加，V8需要在内部将 `x` 的表示形式转换为与 `y` 兼容的浮点数表示形式。 `representation-change.cc` 中的代码会负责插入这个转换操作。

**2. 类型强制转换：**

```javascript
let count = 5;
let message = "You have " + count + " items."; // V8需要将 count 从数字转换为字符串

let isReady = true;
let numericValue = +isReady; // 使用一元加号将布尔值转换为数字 (0 或 1)
```

在第一个例子中，数字 `count` 被拼接到了字符串中，V8需要将其内部表示形式转换为字符串表示形式（通常是 `kTaggedPointer` 指向堆上的字符串对象）。在第二个例子中，布尔值 `isReady` 被强制转换为数字，V8需要将其内部表示形式从布尔值转换为数字 (0或1)。

**3. 位运算：**

```javascript
let a = 15;   // 内部可能表示为 kWord32
let b = 7;    // 内部可能表示为 kWord32

let result = a & b; // 位与运算，通常在 kWord32 表示形式上进行
```

位运算通常在整数的底层表示形式上进行。如果变量的内部表示形式不是 `kWord32`，V8可能需要进行转换才能执行位运算。

**4. BigInt运算：**

```javascript
const bigNumber = 9007199254740991n; // BigInt 类型
let num = 10;

// let sumBig = bigNumber + num; // 错误：不能直接将 BigInt 与 Number 相加
let sumBig = bigNumber + BigInt(num); // 需要将 num 转换为 BigInt

let word64Value = bigNumber & 0xFFFFFFFFFFFFFFFFn; // 对 BigInt 进行位运算，可能涉及 kWord64 的表示
```

当涉及到 `BigInt` 类型的运算时，V8需要确保操作数都以 `BigInt` 的表示形式存在。如果需要将普通的 `Number` 转换为 `BigInt`，`representation-change.cc` 中的代码会处理这种转换。

**总结：**

虽然我们编写JavaScript代码时不需要显式地考虑值的内部表示形式，但V8引擎在底层会进行大量的表示形式转换来保证代码的正确执行和性能。 `representation-change.cc` 文件就是负责管理这些底层转换的关键组成部分。理解它的功能有助于我们更深入地理解JavaScript引擎的工作原理。

### 提示词
```
这是目录为v8/src/compiler/representation-change.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/representation-change.h"

#include <sstream>

#include "src/base/safe_conversions.h"
#include "src/compiler/js-heap-broker.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/simplified-lowering-verifier.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/type-cache.h"
#include "src/heap/factory-inl.h"

namespace v8 {
namespace internal {
namespace compiler {

const char* Truncation::description() const {
  switch (kind()) {
    case TruncationKind::kNone:
      return "no-value-use";
    case TruncationKind::kBool:
      return "truncate-to-bool";
    case TruncationKind::kWord32:
      return "truncate-to-word32";
    case TruncationKind::kWord64:
      return "truncate-to-word64";
    case TruncationKind::kOddballAndBigIntToNumber:
      switch (identify_zeros()) {
        case kIdentifyZeros:
          return "truncate-oddball&bigint-to-number (identify zeros)";
        case kDistinguishZeros:
          return "truncate-oddball&bigint-to-number (distinguish zeros)";
      }
    case TruncationKind::kAny:
      switch (identify_zeros()) {
        case kIdentifyZeros:
          return "no-truncation (but identify zeros)";
        case kDistinguishZeros:
          return "no-truncation (but distinguish zeros)";
      }
  }
  UNREACHABLE();
}

// Partial order for truncations:
//
//               kAny <-------+
//                 ^          |
//                 |          |
//  kOddballAndBigIntToNumber |
//               ^            |
//               /            |
//        kWord64             |
//             ^              |
//             |              |
//        kWord32           kBool
//              ^            ^
//              \            /
//               \          /
//                \        /
//                 \      /
//                  \    /
//                  kNone
//
// TODO(jarin) We might consider making kBool < kOddballAndBigIntToNumber.

// static
Truncation::TruncationKind Truncation::Generalize(TruncationKind rep1,
                                                  TruncationKind rep2) {
  if (LessGeneral(rep1, rep2)) return rep2;
  if (LessGeneral(rep2, rep1)) return rep1;
  // Handle the generalization of float64-representable values.
  if (LessGeneral(rep1, TruncationKind::kOddballAndBigIntToNumber) &&
      LessGeneral(rep2, TruncationKind::kOddballAndBigIntToNumber)) {
    return TruncationKind::kOddballAndBigIntToNumber;
  }
  // Handle the generalization of any-representable values.
  if (LessGeneral(rep1, TruncationKind::kAny) &&
      LessGeneral(rep2, TruncationKind::kAny)) {
    return TruncationKind::kAny;
  }
  // All other combinations are illegal.
  FATAL("Tried to combine incompatible truncations");
}

// static
IdentifyZeros Truncation::GeneralizeIdentifyZeros(IdentifyZeros i1,
                                                  IdentifyZeros i2) {
  if (i1 == i2) {
    return i1;
  } else {
    return kDistinguishZeros;
  }
}

// static
bool Truncation::LessGeneral(TruncationKind rep1, TruncationKind rep2) {
  switch (rep1) {
    case TruncationKind::kNone:
      return true;
    case TruncationKind::kBool:
      return rep2 == TruncationKind::kBool || rep2 == TruncationKind::kAny;
    case TruncationKind::kWord32:
      return rep2 == TruncationKind::kWord32 ||
             rep2 == TruncationKind::kWord64 ||
             rep2 == TruncationKind::kOddballAndBigIntToNumber ||
             rep2 == TruncationKind::kAny;
    case TruncationKind::kWord64:
      return rep2 == TruncationKind::kWord64 ||
             rep2 == TruncationKind::kOddballAndBigIntToNumber ||
             rep2 == TruncationKind::kAny;
    case TruncationKind::kOddballAndBigIntToNumber:
      return rep2 == TruncationKind::kOddballAndBigIntToNumber ||
             rep2 == TruncationKind::kAny;
    case TruncationKind::kAny:
      return rep2 == TruncationKind::kAny;
  }
  UNREACHABLE();
}

// static
bool Truncation::LessGeneralIdentifyZeros(IdentifyZeros i1, IdentifyZeros i2) {
  return i1 == i2 || i1 == kIdentifyZeros;
}

namespace {

bool IsWord(MachineRepresentation rep) {
  return rep == MachineRepresentation::kWord8 ||
         rep == MachineRepresentation::kWord16 ||
         rep == MachineRepresentation::kWord32;
}

bool TypeCheckIsBigInt(TypeCheckKind type_check) {
  return type_check == TypeCheckKind::kBigInt ||
         type_check == TypeCheckKind::kBigInt64;
}

}  // namespace

RepresentationChanger::RepresentationChanger(
    JSGraph* jsgraph, JSHeapBroker* broker,
    SimplifiedLoweringVerifier* verifier)
    : cache_(TypeCache::Get()),
      jsgraph_(jsgraph),
      broker_(broker),
      verifier_(verifier),
      testing_type_errors_(false),
      type_error_(false) {}

// Changes representation from {output_rep} to {use_rep}. The {truncation}
// parameter is only used for checking - if the changer cannot figure
// out signedness for the word32->float64 conversion, then we check that the
// uses truncate to word32 (so they do not care about signedness).
Node* RepresentationChanger::GetRepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Node* use_node, UseInfo use_info) {
  // We are currently not inserting conversions in machine graphs.
  // We might add that, though.
  DCHECK_IMPLIES(!output_type.IsNone(), !output_type.Is(Type::Machine()));
  if (output_rep == MachineRepresentation::kNone && !output_type.IsNone()) {
    // The output representation should be set if the type is inhabited (i.e.,
    // if the value is possible).
    return TypeError(node, output_rep, output_type, use_info.representation());
  }

  // Rematerialize any truncated BigInt if user is not expecting a BigInt.
  if (output_type.Is(Type::BigInt()) &&
      output_rep == MachineRepresentation::kWord64 &&
      !TypeCheckIsBigInt(use_info.type_check())) {
    if (output_type.Is(Type::UnsignedBigInt64())) {
      node = InsertConversion(node, simplified()->ChangeUint64ToBigInt(),
                              use_node);
    } else {
      node =
          InsertConversion(node, simplified()->ChangeInt64ToBigInt(), use_node);
    }
    output_rep = MachineRepresentation::kTaggedPointer;
  }

  // Handle the no-op shortcuts when no checking is necessary.
  if (use_info.type_check() == TypeCheckKind::kNone ||
      // TODO(nicohartmann@, chromium:1077804): Ignoring {use_info.type_check()}
      // in case the representation already matches is not correct. For now,
      // this behavior is disabled only for TypeCheckKind::kBigInt, but should
      // be fixed for all other type checks.
      (output_rep != MachineRepresentation::kWord32 &&
       !TypeCheckIsBigInt(use_info.type_check()))) {
    if (use_info.representation() == output_rep) {
      // Representations are the same. That's a no-op.
      return node;
    }
    if (IsWord(use_info.representation()) && IsWord(output_rep)) {
      // Both are words less than or equal to 32-bits.
      // Since loads of integers from memory implicitly sign or zero extend the
      // value to the full machine word size and stores implicitly truncate,
      // no representation change is necessary.
      return node;
    }
  }

  switch (use_info.representation()) {
    case MachineRepresentation::kTaggedSigned:
      DCHECK(use_info.type_check() == TypeCheckKind::kNone ||
             use_info.type_check() == TypeCheckKind::kSignedSmall);
      return GetTaggedSignedRepresentationFor(node, output_rep, output_type,
                                              use_node, use_info);
    case MachineRepresentation::kTaggedPointer:
      DCHECK(use_info.type_check() == TypeCheckKind::kNone ||
             use_info.type_check() == TypeCheckKind::kHeapObject ||
             use_info.type_check() == TypeCheckKind::kBigInt);
      return GetTaggedPointerRepresentationFor(node, output_rep, output_type,
                                               use_node, use_info);
    case MachineRepresentation::kTagged:
      DCHECK_EQ(TypeCheckKind::kNone, use_info.type_check());
      return GetTaggedRepresentationFor(node, output_rep, output_type,
                                        use_info.truncation());
    case MachineRepresentation::kFloat16:
    case MachineRepresentation::kFloat32:
      DCHECK_EQ(TypeCheckKind::kNone, use_info.type_check());
      return GetFloat32RepresentationFor(node, output_rep, output_type,
                                         use_info.truncation());
    case MachineRepresentation::kFloat64:
      DCHECK(use_info.type_check() == TypeCheckKind::kNone ||
             use_info.type_check() == TypeCheckKind::kNumber ||
             use_info.type_check() == TypeCheckKind::kNumberOrBoolean ||
             use_info.type_check() == TypeCheckKind::kNumberOrOddball);
      return GetFloat64RepresentationFor(node, output_rep, output_type,
                                         use_node, use_info);
    case MachineRepresentation::kBit:
      DCHECK_EQ(TypeCheckKind::kNone, use_info.type_check());
      return GetBitRepresentationFor(node, output_rep, output_type);
    case MachineRepresentation::kWord8:
    case MachineRepresentation::kWord16:
    case MachineRepresentation::kWord32:
      return GetWord32RepresentationFor(node, output_rep, output_type, use_node,
                                        use_info);
    case MachineRepresentation::kWord64:
      DCHECK(use_info.type_check() == TypeCheckKind::kNone ||
             use_info.type_check() == TypeCheckKind::kSigned64 ||
             TypeCheckIsBigInt(use_info.type_check()) ||
             use_info.type_check() == TypeCheckKind::kArrayIndex);
      return GetWord64RepresentationFor(node, output_rep, output_type, use_node,
                                        use_info);
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kNone:
      return node;
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kSandboxedPointer:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kIndirectPointer:
    case MachineRepresentation::kMapWord:
      UNREACHABLE();
  }
  UNREACHABLE();
}

Node* RepresentationChanger::GetTaggedSignedRepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Node* use_node, UseInfo use_info) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kNumberConstant:
      if (output_type.Is(Type::SignedSmall())) {
        return node;
      }
      break;
    default:
      break;
  }
  // Select the correct X -> Tagged operator.
  const Operator* op;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kTaggedSigned),
        node);
  } else if (IsWord(output_rep)) {
    if (output_type.Is(Type::Signed31())) {
      op = simplified()->ChangeInt31ToTaggedSigned();
    } else if (output_type.Is(Type::Signed32())) {
      if (SmiValuesAre32Bits()) {
        op = simplified()->ChangeInt32ToTagged();
      } else if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
        op = simplified()->CheckedInt32ToTaggedSigned(use_info.feedback());
      } else {
        return TypeError(node, output_rep, output_type,
                         MachineRepresentation::kTaggedSigned);
      }
    } else if (output_type.Is(Type::Unsigned32()) &&
               use_info.type_check() == TypeCheckKind::kSignedSmall) {
      op = simplified()->CheckedUint32ToTaggedSigned(use_info.feedback());
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedSigned);
    }
  } else if (output_rep == MachineRepresentation::kWord64) {
    if (output_type.Is(Type::Signed31())) {
      // int64 -> int32 -> tagged signed
      node = InsertTruncateInt64ToInt32(node);
      op = simplified()->ChangeInt31ToTaggedSigned();
    } else if (output_type.Is(Type::Signed32()) && SmiValuesAre32Bits()) {
      // int64 -> int32 -> tagged signed
      node = InsertTruncateInt64ToInt32(node);
      op = simplified()->ChangeInt32ToTagged();
    } else if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
      if (output_type.Is(cache_->kPositiveSafeInteger)) {
        op = simplified()->CheckedUint64ToTaggedSigned(use_info.feedback());
      } else if (output_type.Is(cache_->kSafeInteger)) {
        op = simplified()->CheckedInt64ToTaggedSigned(use_info.feedback());
      } else {
        return TypeError(node, output_rep, output_type,
                         MachineRepresentation::kTaggedSigned);
      }
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedSigned);
    }
  } else if (output_rep == MachineRepresentation::kFloat64) {
    if (output_type.Is(Type::Signed31())) {
      // float64 -> int32 -> tagged signed
      node = InsertChangeFloat64ToInt32(node);
      op = simplified()->ChangeInt31ToTaggedSigned();
    } else if (output_type.Is(Type::Signed32())) {
      // float64 -> int32 -> tagged signed
      node = InsertChangeFloat64ToInt32(node);
      if (SmiValuesAre32Bits()) {
        op = simplified()->ChangeInt32ToTagged();
      } else if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
        op = simplified()->CheckedInt32ToTaggedSigned(use_info.feedback());
      } else {
        return TypeError(node, output_rep, output_type,
                         MachineRepresentation::kTaggedSigned);
      }
    } else if (output_type.Is(Type::Unsigned32()) &&
               use_info.type_check() == TypeCheckKind::kSignedSmall) {
      // float64 -> uint32 -> tagged signed
      node = InsertChangeFloat64ToUint32(node);
      op = simplified()->CheckedUint32ToTaggedSigned(use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
      node = InsertCheckedFloat64ToInt32(
          node,
          output_type.Maybe(Type::MinusZero())
              ? CheckForMinusZeroMode::kCheckForMinusZero
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback(), use_node);
      if (SmiValuesAre32Bits()) {
        op = simplified()->ChangeInt32ToTagged();
      } else {
        op = simplified()->CheckedInt32ToTaggedSigned(use_info.feedback());
      }
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedSigned);
    }
  } else if (output_rep == MachineRepresentation::kFloat32) {
    if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
      node = InsertChangeFloat32ToFloat64(node);
      node = InsertCheckedFloat64ToInt32(
          node,
          output_type.Maybe(Type::MinusZero())
              ? CheckForMinusZeroMode::kCheckForMinusZero
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback(), use_node);
      if (SmiValuesAre32Bits()) {
        op = simplified()->ChangeInt32ToTagged();
      } else {
        op = simplified()->CheckedInt32ToTaggedSigned(use_info.feedback());
      }
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedSigned);
    }
  } else if (CanBeTaggedPointer(output_rep)) {
    if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
      op = simplified()->CheckedTaggedToTaggedSigned(use_info.feedback());
    } else if (output_type.Is(Type::SignedSmall())) {
      op = simplified()->ChangeTaggedToTaggedSigned();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedSigned);
    }
  } else if (output_rep == MachineRepresentation::kBit) {
    if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
      // TODO(turbofan): Consider adding a Bailout operator that just deopts.
      // Also use that for MachineRepresentation::kPointer case above.
      node = InsertChangeBitToTagged(node);
      op = simplified()->CheckedTaggedToTaggedSigned(use_info.feedback());
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedSigned);
    }
  } else {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kTaggedSigned);
  }
  return InsertConversion(node, op, use_node);
}

Node* RepresentationChanger::GetTaggedPointerRepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Node* use_node, UseInfo use_info) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kHeapConstant:
      if (TypeCheckIsBigInt(use_info.type_check())) break;
      return node;  // No change necessary.
    case IrOpcode::kInt32Constant:
    case IrOpcode::kFloat64Constant:
    case IrOpcode::kFloat32Constant:
      UNREACHABLE();
    default:
      break;
  }
  // Select the correct X -> TaggedPointer operator.
  Operator const* op;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kTaggedPointer),
        node);
  }

  if (TypeCheckIsBigInt(use_info.type_check()) &&
      !output_type.Is(Type::BigInt())) {
    // BigInt checks can only be performed on tagged representations. Note that
    // a corresponding check is inserted down below.
    if (!CanBeTaggedPointer(output_rep)) {
      Node* unreachable =
          InsertUnconditionalDeopt(use_node, DeoptimizeReason::kNotABigInt);
      return jsgraph()->graph()->NewNode(
          jsgraph()->common()->DeadValue(MachineRepresentation::kTaggedPointer),
          unreachable);
    }
  }

  if (output_rep == MachineRepresentation::kBit) {
    if (output_type.Is(Type::Boolean())) {
      op = simplified()->ChangeBitToTagged();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTagged);
    }
  } else if (IsWord(output_rep)) {
    if (output_type.Is(Type::Unsigned32())) {
      // uint32 -> float64 -> tagged
      node = InsertChangeUint32ToFloat64(node);
    } else if (output_type.Is(Type::Signed32())) {
      // int32 -> float64 -> tagged
      node = InsertChangeInt32ToFloat64(node);
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedPointer);
    }
    op = simplified()->ChangeFloat64ToTaggedPointer();
  } else if (output_rep == MachineRepresentation::kWord64) {
    if (output_type.Is(cache_->kSafeInteger)) {
      // int64 -> float64 -> tagged pointer
      op = machine()->ChangeInt64ToFloat64();
      node = jsgraph()->graph()->NewNode(op, node);
      op = simplified()->ChangeFloat64ToTaggedPointer();
    } else if (output_type.Is(Type::SignedBigInt64()) &&
               use_info.type_check() == TypeCheckKind::kBigInt) {
      op = simplified()->ChangeInt64ToBigInt();
    } else if (output_type.Is(Type::UnsignedBigInt64()) &&
               use_info.type_check() == TypeCheckKind::kBigInt) {
      op = simplified()->ChangeUint64ToBigInt();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedPointer);
    }
  } else if (output_rep == MachineRepresentation::kFloat32) {
    if (output_type.Is(Type::Number())) {
      // float32 -> float64 -> tagged
      node = InsertChangeFloat32ToFloat64(node);
      op = simplified()->ChangeFloat64ToTaggedPointer();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedPointer);
    }
  } else if (output_rep == MachineRepresentation::kFloat64) {
    if (output_type.Is(Type::Number())) {
      // float64 -> tagged
      op = simplified()->ChangeFloat64ToTaggedPointer();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTaggedPointer);
    }
  } else if (IsAnyTagged(output_rep)) {
    if (use_info.type_check() == TypeCheckKind::kBigInt) {
      if (output_type.Is(Type::BigInt())) {
        DCHECK_NE(output_rep, MachineRepresentation::kTaggedSigned);
        return node;
      }
      op = simplified()->CheckBigInt(use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kBigInt64) {
      if (output_type.Is(Type::SignedBigInt64())) {
        DCHECK_NE(output_rep, MachineRepresentation::kTaggedSigned);
        return node;
      }
      if (!output_type.Is(Type::BigInt())) {
        node = InsertConversion(
            node, simplified()->CheckBigInt(use_info.feedback()), use_node);
      }
      op = simplified()->CheckedBigIntToBigInt64(use_info.feedback());
    } else if (output_rep == MachineRepresentation::kTaggedPointer ||
               !output_type.Maybe(Type::SignedSmall())) {
      DCHECK_NE(output_rep, MachineRepresentation::kTaggedSigned);
      return node;
    } else {
      op = simplified()->CheckedTaggedToTaggedPointer(use_info.feedback());
    }
  } else {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kTaggedPointer);
  }
  return InsertConversion(node, op, use_node);
}

Node* RepresentationChanger::GetTaggedRepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Truncation truncation) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kNumberConstant:
    case IrOpcode::kHeapConstant:
      return node;  // No change necessary.
    case IrOpcode::kInt32Constant:
    case IrOpcode::kFloat64Constant:
    case IrOpcode::kFloat32Constant:
      UNREACHABLE();
    default:
      break;
  }
  if (output_rep == MachineRepresentation::kTaggedSigned ||
      output_rep == MachineRepresentation::kTaggedPointer ||
      output_rep == MachineRepresentation::kMapWord) {
    // this is a no-op.
    return node;
  }
  // Select the correct X -> Tagged operator.
  const Operator* op;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kTagged), node);
  } else if (output_rep == MachineRepresentation::kBit) {
    if (output_type.Is(Type::Boolean())) {
      op = simplified()->ChangeBitToTagged();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTagged);
    }
  } else if (IsWord(output_rep)) {
    if (output_type.Is(Type::Signed31())) {
      op = simplified()->ChangeInt31ToTaggedSigned();
    } else if (output_type.Is(Type::Signed32()) ||
               (output_type.Is(Type::Signed32OrMinusZero()) &&
                truncation.IdentifiesZeroAndMinusZero())) {
      op = simplified()->ChangeInt32ToTagged();
    } else if (output_type.Is(Type::Unsigned32()) ||
               (output_type.Is(Type::Unsigned32OrMinusZero()) &&
                truncation.IdentifiesZeroAndMinusZero()) ||
               truncation.IsUsedAsWord32()) {
      // Either the output is uint32 or the uses only care about the
      // low 32 bits (so we can pick uint32 safely).
      op = simplified()->ChangeUint32ToTagged();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTagged);
    }
  } else if (output_rep == MachineRepresentation::kWord64) {
    if (output_type.Is(Type::Signed31())) {
      // int64 -> int32 -> tagged signed
      node = InsertTruncateInt64ToInt32(node);
      op = simplified()->ChangeInt31ToTaggedSigned();
    } else if (output_type.Is(Type::Signed32())) {
      // int64 -> int32 -> tagged
      node = InsertTruncateInt64ToInt32(node);
      op = simplified()->ChangeInt32ToTagged();
    } else if (output_type.Is(Type::Unsigned32())) {
      // int64 -> uint32 -> tagged
      node = InsertTruncateInt64ToInt32(node);
      op = simplified()->ChangeUint32ToTagged();
    } else if (output_type.Is(cache_->kPositiveSafeInteger)) {
      // uint64 -> tagged
      op = simplified()->ChangeUint64ToTagged();
    } else if (output_type.Is(cache_->kSafeInteger)) {
      // int64 -> tagged
      op = simplified()->ChangeInt64ToTagged();
    } else if (output_type.Is(Type::SignedBigInt64())) {
      // int64 -> BigInt
      op = simplified()->ChangeInt64ToBigInt();
    } else if (output_type.Is(Type::UnsignedBigInt64())) {
      // uint64 -> BigInt
      op = simplified()->ChangeUint64ToBigInt();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTagged);
    }
  } else if (output_rep ==
             MachineRepresentation::kFloat32) {  // float32 -> float64 -> tagged
    node = InsertChangeFloat32ToFloat64(node);
    op = simplified()->ChangeFloat64ToTagged(
        output_type.Maybe(Type::MinusZero())
            ? CheckForMinusZeroMode::kCheckForMinusZero
            : CheckForMinusZeroMode::kDontCheckForMinusZero);
  } else if (output_rep == MachineRepresentation::kFloat64) {
    if (output_type.Is(Type::Signed31())) {  // float64 -> int32 -> tagged
      node = InsertChangeFloat64ToInt32(node);
      op = simplified()->ChangeInt31ToTaggedSigned();
    } else if (output_type.Is(
                   Type::Signed32())) {  // float64 -> int32 -> tagged
      node = InsertChangeFloat64ToInt32(node);
      op = simplified()->ChangeInt32ToTagged();
    } else if (output_type.Is(
                   Type::Unsigned32())) {  // float64 -> uint32 -> tagged
      node = InsertChangeFloat64ToUint32(node);
      op = simplified()->ChangeUint32ToTagged();
    } else if (output_type.Is(Type::Number()) ||
               (output_type.Is(Type::NumberOrOddball()) &&
                truncation.TruncatesOddballAndBigIntToNumber())) {
      op = simplified()->ChangeFloat64ToTagged(
          output_type.Maybe(Type::MinusZero())
              ? CheckForMinusZeroMode::kCheckForMinusZero
              : CheckForMinusZeroMode::kDontCheckForMinusZero);
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kTagged);
    }
  } else {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kTagged);
  }
  return jsgraph()->graph()->NewNode(op, node);
}

Node* RepresentationChanger::GetFloat32RepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Truncation truncation) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kNumberConstant:
      return jsgraph()->Float32Constant(
          DoubleToFloat32(OpParameter<double>(node->op())));
    case IrOpcode::kInt32Constant:
    case IrOpcode::kFloat64Constant:
    case IrOpcode::kFloat32Constant:
      UNREACHABLE();
    default:
      break;
  }
  // Select the correct X -> Float32 operator.
  const Operator* op = nullptr;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kFloat32), node);
  } else if (IsWord(output_rep)) {
    if (output_type.Is(Type::Signed32())) {
      // int32 -> float64 -> float32
      op = machine()->ChangeInt32ToFloat64();
      node = jsgraph()->graph()->NewNode(op, node);
      op = machine()->TruncateFloat64ToFloat32();
    } else if (output_type.Is(Type::Unsigned32()) ||
               truncation.IsUsedAsWord32()) {
      // Either the output is uint32 or the uses only care about the
      // low 32 bits (so we can pick uint32 safely).

      // uint32 -> float64 -> float32
      op = machine()->ChangeUint32ToFloat64();
      node = jsgraph()->graph()->NewNode(op, node);
      op = machine()->TruncateFloat64ToFloat32();
    }
  } else if (IsAnyTagged(output_rep)) {
    if (output_type.Is(Type::NumberOrOddball())) {
      // tagged -> float64 -> float32
      if (output_type.Is(Type::Number())) {
        op = simplified()->ChangeTaggedToFloat64();
      } else {
        op = simplified()->TruncateTaggedToFloat64();
      }
      node = jsgraph()->graph()->NewNode(op, node);
      op = machine()->TruncateFloat64ToFloat32();
    }
  } else if (output_rep == MachineRepresentation::kFloat64) {
    op = machine()->TruncateFloat64ToFloat32();
  } else if (output_rep == MachineRepresentation::kWord64) {
    if (output_type.Is(cache_->kSafeInteger)) {
      // int64 -> float64 -> float32
      op = machine()->ChangeInt64ToFloat64();
      node = jsgraph()->graph()->NewNode(op, node);
      op = machine()->TruncateFloat64ToFloat32();
    }
  }
  if (op == nullptr) {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kFloat32);
  }
  return jsgraph()->graph()->NewNode(op, node);
}

Node* RepresentationChanger::GetFloat64RepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Node* use_node, UseInfo use_info) {
  NumberMatcher m(node);
  if (m.HasResolvedValue()) {
    // BigInts are not used as number constants.
    DCHECK(!TypeCheckIsBigInt(use_info.type_check()));
    switch (use_info.type_check()) {
      case TypeCheckKind::kNone:
      case TypeCheckKind::kNumber:
      case TypeCheckKind::kNumberOrBoolean:
      case TypeCheckKind::kNumberOrOddball:
        return jsgraph()->Float64Constant(m.ResolvedValue());
      case TypeCheckKind::kBigInt:
      case TypeCheckKind::kBigInt64:
      case TypeCheckKind::kHeapObject:
      case TypeCheckKind::kSigned32:
      case TypeCheckKind::kSigned64:
      case TypeCheckKind::kSignedSmall:
      case TypeCheckKind::kArrayIndex:
        break;
    }
  }
  // Select the correct X -> Float64 operator.
  const Operator* op = nullptr;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kFloat64), node);
  } else if (IsWord(output_rep)) {
    if (output_type.Is(Type::Signed32()) ||
        (output_type.Is(Type::Signed32OrMinusZero()) &&
         use_info.truncation().IdentifiesZeroAndMinusZero())) {
      op = machine()->ChangeInt32ToFloat64();
    } else if (output_type.Is(Type::Unsigned32()) ||
               (output_type.Is(Type::Unsigned32OrMinusZero()) &&
                use_info.truncation().IdentifiesZeroAndMinusZero()) ||
               use_info.truncation().IsUsedAsWord32()) {
      // Either the output is uint32 or the uses only care about the
      // low 32 bits (so we can pick uint32 safely).
      op = machine()->ChangeUint32ToFloat64();
    }
  } else if (output_rep == MachineRepresentation::kBit) {
    CHECK(output_type.Is(Type::Boolean()));
    if (use_info.truncation().TruncatesOddballAndBigIntToNumber() ||
        use_info.type_check() == TypeCheckKind::kNumberOrBoolean ||
        use_info.type_check() == TypeCheckKind::kNumberOrOddball) {
      op = machine()->ChangeUint32ToFloat64();
    } else {
      CHECK_NE(use_info.type_check(), TypeCheckKind::kNone);
      Node* unreachable =
          InsertUnconditionalDeopt(use_node, DeoptimizeReason::kNotAHeapNumber);
      return jsgraph()->graph()->NewNode(
          jsgraph()->common()->DeadValue(MachineRepresentation::kFloat64),
          unreachable);
    }
  } else if (IsAnyTagged(output_rep)) {
    if (output_type.Is(Type::Undefined())) {
      if (use_info.type_check() == TypeCheckKind::kNumberOrOddball ||
          (use_info.type_check() == TypeCheckKind::kNone &&
           use_info.truncation().TruncatesOddballAndBigIntToNumber())) {
        return jsgraph()->Float64Constant(
            std::numeric_limits<double>::quiet_NaN());
      } else {
        DCHECK(use_info.type_check() == TypeCheckKind::kNone ||
               use_info.type_check() == TypeCheckKind::kNumber ||
               use_info.type_check() == TypeCheckKind::kNumberOrBoolean);
        Node* unreachable = InsertUnconditionalDeopt(
            use_node, use_info.type_check() == TypeCheckKind::kNumber
                          ? DeoptimizeReason::kNotANumber
                          : DeoptimizeReason::kNotANumberOrBoolean);
        return jsgraph()->graph()->NewNode(
            jsgraph()->common()->DeadValue(MachineRepresentation::kFloat64),
            unreachable);
      }
    } else if (output_rep == MachineRepresentation::kTaggedSigned) {
      node = InsertChangeTaggedSignedToInt32(node);
      op = machine()->ChangeInt32ToFloat64();
    } else if (output_type.Is(Type::Number())) {
      op = simplified()->ChangeTaggedToFloat64();
    } else if ((output_type.Is(Type::NumberOrOddball()) &&
                use_info.truncation().TruncatesOddballAndBigIntToNumber()) ||
               output_type.Is(Type::NumberOrHole())) {
      // JavaScript 'null' is an Oddball that results in +0 when truncated to
      // Number. In a context like -0 == null, which must evaluate to false,
      // this truncation must not happen. For this reason we restrict this
      // case to when either the user explicitly requested a float (and thus
      // wants +0 if null is the input) or we know from the types that the
      // input can only be Number | Hole. The latter is necessary to handle
      // the operator CheckFloat64Hole. We did not put in the type (Number |
      // Oddball \ Null) to discover more bugs related to this conversion via
      // crashes.
      op = simplified()->TruncateTaggedToFloat64();
    } else if (use_info.type_check() == TypeCheckKind::kNumber ||
               (use_info.type_check() == TypeCheckKind::kNumberOrOddball &&
                !output_type.Maybe(Type::BooleanOrNullOrNumber()))) {
      op = simplified()->CheckedTaggedToFloat64(CheckTaggedInputMode::kNumber,
                                                use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kNumberOrBoolean) {
      op = simplified()->CheckedTaggedToFloat64(
          CheckTaggedInputMode::kNumberOrBoolean, use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kNumberOrOddball) {
      op = simplified()->CheckedTaggedToFloat64(
          CheckTaggedInputMode::kNumberOrOddball, use_info.feedback());
    }
  } else if (output_rep == MachineRepresentation::kFloat32) {
    op = machine()->ChangeFloat32ToFloat64();
  } else if (output_rep == MachineRepresentation::kWord64) {
    if (output_type.Is(cache_->kSafeInteger)) {
      op = machine()->ChangeInt64ToFloat64();
    }
  }
  if (op == nullptr) {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kFloat64);
  }
  return InsertConversion(node, op, use_node);
}

Node* RepresentationChanger::MakeTruncatedInt32Constant(double value) {
  return jsgraph()->Int32Constant(DoubleToInt32(value));
}

Node* RepresentationChanger::InsertUnconditionalDeopt(
    Node* node, DeoptimizeReason reason, const FeedbackSource& feedback) {
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  effect =
      jsgraph()->graph()->NewNode(simplified()->CheckIf(reason, feedback),
                                  jsgraph()->Int32Constant(0), effect, control);
  Node* unreachable = effect = jsgraph()->graph()->NewNode(
      jsgraph()->common()->Unreachable(), effect, control);
  NodeProperties::ReplaceEffectInput(node, effect);
  return unreachable;
}

Node* RepresentationChanger::GetWord32RepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Node* use_node, UseInfo use_info) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kInt32Constant:
    case IrOpcode::kInt64Constant:
    case IrOpcode::kFloat32Constant:
    case IrOpcode::kFloat64Constant:
      UNREACHABLE();
    case IrOpcode::kNumberConstant: {
      double const fv = OpParameter<double>(node->op());
      if (use_info.type_check() == TypeCheckKind::kNone ||
          ((use_info.type_check() == TypeCheckKind::kSignedSmall ||
            use_info.type_check() == TypeCheckKind::kSigned32 ||
            use_info.type_check() == TypeCheckKind::kNumber ||
            use_info.type_check() == TypeCheckKind::kNumberOrOddball ||
            use_info.type_check() == TypeCheckKind::kArrayIndex) &&
           IsInt32Double(fv))) {
        return InsertTypeOverrideForVerifier(NodeProperties::GetType(node),
                                             MakeTruncatedInt32Constant(fv));
      }
      break;
    }
    default:
      break;
  }

  // Select the correct X -> Word32 operator.
  const Operator* op = nullptr;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kWord32), node);
  } else if (output_rep == MachineRepresentation::kBit) {
    CHECK(output_type.Is(Type::Boolean()));
    if (use_info.truncation().IsUsedAsWord32()) {
      return node;
    } else {
      CHECK(Truncation::Any(kIdentifyZeros)
                .IsLessGeneralThan(use_info.truncation()));
      CHECK_NE(use_info.type_check(), TypeCheckKind::kNone);
      CHECK_NE(use_info.type_check(), TypeCheckKind::kNumberOrOddball);
      Node* unreachable =
          InsertUnconditionalDeopt(use_node, DeoptimizeReason::kNotASmi);
      return jsgraph()->graph()->NewNode(
          jsgraph()->common()->DeadValue(MachineRepresentation::kWord32),
          unreachable);
    }
  } else if (output_rep == MachineRepresentation::kFloat64) {
    if (output_type.Is(Type::Signed32())) {
      op = machine()->ChangeFloat64ToInt32();
    } else if (use_info.type_check() == TypeCheckKind::kSignedSmall ||
               use_info.type_check() == TypeCheckKind::kSigned32 ||
               use_info.type_check() == TypeCheckKind::kArrayIndex) {
      op = simplified()->CheckedFloat64ToInt32(
          output_type.Maybe(Type::MinusZero())
              ? use_info.minus_zero_check()
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback());
    } else if (output_type.Is(Type::Unsigned32())) {
      op = machine()->ChangeFloat64ToUint32();
    } else if (use_info.truncation().IsUsedAsWord32()) {
      op = machine()->TruncateFloat64ToWord32();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord32);
    }
  } else if (output_rep == MachineRepresentation::kFloat32) {
    node = InsertChangeFloat32ToFloat64(node);  // float32 -> float64 -> int32
    if (output_type.Is(Type::Signed32())) {
      op = machine()->ChangeFloat64ToInt32();
    } else if (use_info.type_check() == TypeCheckKind::kSignedSmall ||
               use_info.type_check() == TypeCheckKind::kSigned32 ||
               use_info.type_check() == TypeCheckKind::kArrayIndex) {
      op = simplified()->CheckedFloat64ToInt32(
          output_type.Maybe(Type::MinusZero())
              ? use_info.minus_zero_check()
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback());
    } else if (output_type.Is(Type::Unsigned32())) {
      op = machine()->ChangeFloat64ToUint32();
    } else if (use_info.truncation().IsUsedAsWord32()) {
      op = machine()->TruncateFloat64ToWord32();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord32);
    }
  } else if (IsAnyTagged(output_rep)) {
    if (output_rep == MachineRepresentation::kTaggedSigned &&
        output_type.Is(Type::SignedSmall())) {
      op = simplified()->ChangeTaggedSignedToInt32();
    } else if (output_type.Is(Type::Signed32())) {
      op = simplified()->ChangeTaggedToInt32();
    } else if (use_info.type_check() == TypeCheckKind::kSignedSmall) {
      op = simplified()->CheckedTaggedSignedToInt32(use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kSigned32) {
      op = simplified()->CheckedTaggedToInt32(
          output_type.Maybe(Type::MinusZero())
              ? use_info.minus_zero_check()
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kArrayIndex) {
      op = simplified()->CheckedTaggedToArrayIndex(use_info.feedback());
    } else if (output_type.Is(Type::Unsigned32())) {
      op = simplified()->ChangeTaggedToUint32();
    } else if (use_info.truncation().IsUsedAsWord32()) {
      if (output_type.Is(Type::NumberOrOddballOrHole())) {
        op = simplified()->TruncateTaggedToWord32();
      } else if (use_info.type_check() == TypeCheckKind::kNumber) {
        op = simplified()->CheckedTruncateTaggedToWord32(
            CheckTaggedInputMode::kNumber, use_info.feedback());
      } else if (use_info.type_check() == TypeCheckKind::kNumberOrOddball) {
        op = simplified()->CheckedTruncateTaggedToWord32(
            CheckTaggedInputMode::kNumberOrOddball, use_info.feedback());
      } else {
        return TypeError(node, output_rep, output_type,
                         MachineRepresentation::kWord32);
      }
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord32);
    }
  } else if (output_rep == MachineRepresentation::kWord32) {
    // Only the checked case should get here, the non-checked case is
    // handled in GetRepresentationFor.
    if (use_info.type_check() == TypeCheckKind::kSignedSmall ||
        use_info.type_check() == TypeCheckKind::kSigned32 ||
        use_info.type_check() == TypeCheckKind::kArrayIndex) {
      bool identify_zeros = use_info.truncation().IdentifiesZeroAndMinusZero();
      if (output_type.Is(Type::Signed32()) ||
          (identify_zeros && output_type.Is(Type::Signed32OrMinusZero()))) {
        return node;
      } else if (output_type.Is(Type::Unsigned32()) ||
                 (identify_zeros &&
                  output_type.Is(Type::Unsigned32OrMinusZero()))) {
        op = simplified()->CheckedUint32ToInt32(use_info.feedback());
      } else {
        return TypeError(node, output_rep, output_type,
                         MachineRepresentation::kWord32);
      }
    } else if (use_info.type_check() == TypeCheckKind::kNumber ||
               use_info.type_check() == TypeCheckKind::kNumberOrOddball) {
      return node;
    }
  } else if (output_rep == MachineRepresentation::kWord8 ||
             output_rep == MachineRepresentation::kWord16) {
    DCHECK_EQ(MachineRepresentation::kWord32, use_info.representation());
    DCHECK(use_info.type_check() == TypeCheckKind::kSignedSmall ||
           use_info.type_check() == TypeCheckKind::kSigned32);
    return node;
  } else if (output_rep == MachineRepresentation::kWord64) {
    if (output_type.Is(Type::Signed32()) ||
        (output_type.Is(Type::Unsigned32()) &&
         use_info.type_check() == TypeCheckKind::kNone) ||
        (output_type.Is(cache_->kSafeInteger) &&
         use_info.truncation().IsUsedAsWord32())) {
      op = machine()->TruncateInt64ToInt32();
    } else if (use_info.type_check() == TypeCheckKind::kSignedSmall ||
               use_info.type_check() == TypeCheckKind::kSigned32 ||
               use_info.type_check() == TypeCheckKind::kArrayIndex) {
      if (output_type.Is(cache_->kPositiveSafeInteger)) {
        op = simplified()->CheckedUint64ToInt32(use_info.feedback());
      } else if (output_type.Is(cache_->kSafeInteger)) {
        op = simplified()->CheckedInt64ToInt32(use_info.feedback());
      } else {
        return TypeError(node, output_rep, output_type,
                         MachineRepresentation::kWord32);
      }
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord32);
    }
  }

  if (op == nullptr) {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kWord32);
  }
  return InsertConversion(node, op, use_node);
}

Node* RepresentationChanger::InsertConversion(Node* node, const Operator* op,
                                              Node* use_node) {
  if (op->ControlInputCount() > 0) {
    // If the operator can deoptimize (which means it has control
    // input), we need to connect it to the effect and control chains.
    Node* effect = NodeProperties::GetEffectInput(use_node);
    Node* control = NodeProperties::GetControlInput(use_node);
    Node* conversion = jsgraph()->graph()->NewNode(op, node, effect, control);
    NodeProperties::ReplaceEffectInput(use_node, conversion);
    return conversion;
  }
  return jsgraph()->graph()->NewNode(op, node);
}

Node* RepresentationChanger::GetBitRepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kHeapConstant: {
      HeapObjectMatcher m(node);
      if (m.Is(factory()->false_value())) {
        return InsertTypeOverrideForVerifier(
            Type::Constant(broker_, broker_->false_value(), jsgraph()->zone()),
            jsgraph()->Int32Constant(0));
      } else if (m.Is(factory()->true_value())) {
        return InsertTypeOverrideForVerifier(
            Type::Constant(broker_, broker_->true_value(), jsgraph()->zone()),
            jsgraph()->Int32Constant(1));
      }
      break;
    }
    default:
      break;
  }
  // Select the correct X -> Bit operator.
  const Operator* op;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kBit), node);
  } else if (output_rep == MachineRepresentation::kTagged ||
             output_rep == MachineRepresentation::kTaggedPointer) {
    if (output_type.Is(Type::BooleanOrNullOrUndefined())) {
      // true is the only trueish Oddball.
      op = simplified()->ChangeTaggedToBit();
    } else {
      if (output_rep == MachineRepresentation::kTagged &&
          output_type.Maybe(Type::SignedSmall())) {
        op = simplified()->TruncateTaggedToBit();
      } else {
        // The {output_type} either doesn't include the Smi range,
        // or the {output_rep} is known to be TaggedPointer.
        op = simplified()->TruncateTaggedPointerToBit();
      }
    }
  } else if (output_rep == MachineRepresentation::kTaggedSigned) {
    if (COMPRESS_POINTERS_BOOL) {
      node = jsgraph()->graph()->NewNode(machine()->Word32Equal(), node,
                                         jsgraph()->Int32Constant(0));
    } else {
      node = jsgraph()->graph()->NewNode(machine()->WordEqual(), node,
                                         jsgraph()->IntPtrConstant(0));
    }
    return jsgraph()->graph()->NewNode(machine()->Word32Equal(), node,
                                       jsgraph()->Int32Constant(0));
  } else if (IsWord(output_rep)) {
    node = jsgraph()->graph()->NewNode(machine()->Word32Equal(), node,
                                       jsgraph()->Int32Constant(0));
    return jsgraph()->graph()->NewNode(machine()->Word32Equal(), node,
                                       jsgraph()->Int32Constant(0));
  } else if (output_rep == MachineRepresentation::kWord64) {
    node = jsgraph()->graph()->NewNode(machine()->Word64Equal(), node,
                                       jsgraph()->Int64Constant(0));
    return jsgraph()->graph()->NewNode(machine()->Word32Equal(), node,
                                       jsgraph()->Int32Constant(0));
  } else if (output_rep == MachineRepresentation::kFloat32) {
    node = jsgraph()->graph()->NewNode(machine()->Float32Abs(), node);
    return jsgraph()->graph()->NewNode(machine()->Float32LessThan(),
                                       jsgraph()->Float32Constant(0.0), node);
  } else if (output_rep == MachineRepresentation::kFloat64) {
    node = jsgraph()->graph()->NewNode(machine()->Float64Abs(), node);
    return jsgraph()->graph()->NewNode(machine()->Float64LessThan(),
                                       jsgraph()->Float64Constant(0.0), node);
  } else {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kBit);
  }
  return jsgraph()->graph()->NewNode(op, node);
}

Node* RepresentationChanger::GetWord64RepresentationFor(
    Node* node, MachineRepresentation output_rep, Type output_type,
    Node* use_node, UseInfo use_info) {
  // Eagerly fold representation changes for constants.
  switch (node->opcode()) {
    case IrOpcode::kInt32Constant:
    case IrOpcode::kInt64Constant:
    case IrOpcode::kFloat32Constant:
    case IrOpcode::kFloat64Constant:
      UNREACHABLE();
    case IrOpcode::kNumberConstant: {
      if (!TypeCheckIsBigInt(use_info.type_check())) {
        double const fv = OpParameter<double>(node->op());
        if (base::IsValueInRangeForNumericType<int64_t>(fv)) {
          int64_t const iv = static_cast<int64_t>(fv);
          if (static_cast<double>(iv) == fv) {
            return InsertTypeOverrideForVerifier(NodeProperties::GetType(node),
                                                 jsgraph()->Int64Constant(iv));
          }
        }
      }
      break;
    }
    case IrOpcode::kHeapConstant: {
      HeapObjectMatcher m(node);
      if (m.HasResolvedValue() && m.Ref(broker_).IsBigInt() &&
          (Is64() && use_info.truncation().IsUsedAsWord64())) {
        BigIntRef bigint = m.Ref(broker_).AsBigInt();
        return InsertTypeOverrideForVerifier(
            NodeProperties::GetType(node),
            jsgraph()->Int64Constant(static_cast<int64_t>(bigint.AsUint64())));
      }
      break;
    }
    default:
      break;
  }

  if (TypeCheckIsBigInt(use_info.type_check())) {
    // BigInts are only represented as tagged pointer and word64.
    if (!CanBeTaggedPointer(output_rep) &&
        output_rep != MachineRepresentation::kWord64) {
      DCHECK(!output_type.Equals(Type::BigInt()));
      Node* unreachable = InsertUnconditionalDeopt(
          use_node, DeoptimizeReason::kNotABigInt, use_info.feedback());
      return jsgraph()->graph()->NewNode(
          jsgraph()->common()->DeadValue(MachineRepresentation::kWord64),
          unreachable);
    }
  }

  // Select the correct X -> Word64 operator.
  const Operator* op;
  if (output_type.Is(Type::None())) {
    // This is an impossible value; it should not be used at runtime.
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kWord64), node);
  } else if (output_rep == MachineRepresentation::kBit) {
    CHECK(output_type.Is(Type::Boolean()));
    CHECK_NE(use_info.type_check(), TypeCheckKind::kNone);
    CHECK_NE(use_info.type_check(), TypeCheckKind::kNumberOrOddball);
    CHECK_NE(use_info.type_check(), TypeCheckKind::kBigInt);
    CHECK_NE(use_info.type_check(), TypeCheckKind::kBigInt64);
    Node* unreachable =
        InsertUnconditionalDeopt(use_node, DeoptimizeReason::kNotASmi);
    return jsgraph()->graph()->NewNode(
        jsgraph()->common()->DeadValue(MachineRepresentation::kWord64),
        unreachable);
  } else if (IsWord(output_rep)) {
    if (output_type.Is(Type::Unsigned32OrMinusZero())) {
      // uint32 -> uint64
      CHECK_IMPLIES(output_type.Maybe(Type::MinusZero()),
                    use_info.truncation().IdentifiesZeroAndMinusZero());
      op = machine()->ChangeUint32ToUint64();
    } else if (output_type.Is(Type::Signed32OrMinusZero())) {
      // int32 -> int64
      CHECK_IMPLIES(output_type.Maybe(Type::MinusZero()),
                    use_info.truncation().IdentifiesZeroAndMinusZero());
      op = machine()->ChangeInt32ToInt64();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord64);
    }
  } else if (output_rep == MachineRepresentation::kFloat32) {
    if (output_type.Is(cache_->kDoubleRepresentableInt64) ||
        (output_type.Is(cache_->kDoubleRepresentableInt64OrMinusZero) &&
         use_info.truncation().IdentifiesZeroAndMinusZero())) {
      // float32 -> float64 -> int64
      node = InsertChangeFloat32ToFloat64(node);
      op = machine()->ChangeFloat64ToInt64();
    } else if (output_type.Is(cache_->kDoubleRepresentableUint64)) {
      // float32 -> float64 -> uint64
      node = InsertChangeFloat32ToFloat64(node);
      op = machine()->ChangeFloat64ToUint64();
    } else if (use_info.type_check() == TypeCheckKind::kSigned64 ||
               use_info.type_check() == TypeCheckKind::kArrayIndex) {
      // float32 -> float64 -> int64
      node = InsertChangeFloat32ToFloat64(node);
      op = simplified()->CheckedFloat64ToInt64(
          output_type.Maybe(Type::MinusZero())
              ? use_info.minus_zero_check()
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback());
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord64);
    }
  } else if (output_rep == MachineRepresentation::kFloat64) {
    if (output_type.Is(cache_->kDoubleRepresentableInt64) ||
        (output_type.Is(cache_->kDoubleRepresentableInt64OrMinusZero) &&
         use_info.truncation().IdentifiesZeroAndMinusZero())) {
      op = machine()->ChangeFloat64ToInt64();
    } else if (output_type.Is(cache_->kDoubleRepresentableUint64)) {
      op = machine()->ChangeFloat64ToUint64();
    } else if (use_info.type_check() == TypeCheckKind::kSigned64 ||
               use_info.type_check() == TypeCheckKind::kArrayIndex) {
      op = simplified()->CheckedFloat64ToInt64(
          output_type.Maybe(Type::MinusZero())
              ? use_info.minus_zero_check()
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback());
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord64);
    }
  } else if (output_rep == MachineRepresentation::kTaggedSigned) {
    if (output_type.Is(Type::SignedSmall())) {
      op = simplified()->ChangeTaggedSignedToInt64();
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord64);
    }
  } else if (IsAnyTagged(output_rep) &&
             ((Is64() && use_info.truncation().IsUsedAsWord64() &&
               (use_info.type_check() == TypeCheckKind::kBigInt ||
                output_type.Is(Type::BigInt()))) ||
              use_info.type_check() == TypeCheckKind::kBigInt64)) {
    node = GetTaggedPointerRepresentationFor(node, output_rep, output_type,
                                             use_node, use_info);
    op = simplified()->TruncateBigIntToWord64();
  } else if (CanBeTaggedPointer(output_rep)) {
    if (output_type.Is(cache_->kDoubleRepresentableInt64) ||
        (output_type.Is(cache_->kDoubleRepresentableInt64OrMinusZero) &&
         use_info.truncation().IdentifiesZeroAndMinusZero())) {
      op = simplified()->ChangeTaggedToInt64();
    } else if (use_info.type_check() == TypeCheckKind::kSigned64) {
      op = simplified()->CheckedTaggedToInt64(
          output_type.Maybe(Type::MinusZero())
              ? use_info.minus_zero_check()
              : CheckForMinusZeroMode::kDontCheckForMinusZero,
          use_info.feedback());
    } else if (use_info.type_check() == TypeCheckKind::kArrayIndex) {
      op = simplified()->CheckedTaggedToArrayIndex(use_info.feedback());
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord64);
    }
  } else if (output_rep == MachineRepresentation::kWord64) {
    DCHECK(TypeCheckIsBigInt(use_info.type_check()));
    if (output_type.Is(Type::UnsignedBigInt64()) &&
        use_info.type_check() == TypeCheckKind::kBigInt64) {
      op = simplified()->CheckedUint64ToInt64(use_info.feedback());
    } else if ((output_type.Is(Type::BigInt()) &&
                use_info.type_check() == TypeCheckKind::kBigInt) ||
               (output_type.Is(Type::SignedBigInt64()) &&
                use_info.type_check() == TypeCheckKind::kBigInt64)) {
      return node;
    } else {
      DCHECK(output_type != Type::BigInt() ||
             use_info.type_check() != TypeCheckKind::kBigInt64);
      Node* unreachable = InsertUnconditionalDeopt(
          use_node, DeoptimizeReason::kNotABigInt, use_info.feedback());
      return jsgraph()->graph()->NewNode(
          jsgraph()->common()->DeadValue(MachineRepresentation::kWord64),
          unreachable);
    }
  } else if (output_rep == MachineRepresentation::kSandboxedPointer) {
    if (output_type.Is(Type::SandboxedPointer())) {
      return node;
    } else {
      return TypeError(node, output_rep, output_type,
                       MachineRepresentation::kWord64);
    }
  } else {
    return TypeError(node, output_rep, output_type,
                     MachineRepresentation::kWord64);
  }
  return InsertConversion(node, op, use_node);
}

const Operator* RepresentationChanger::Int32OperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeNumberAdd:  // Fall through.
    case IrOpcode::kSpeculativeSafeIntegerAdd:
    case IrOpcode::kNumberAdd:
      return machine()->Int32Add();
    case IrOpcode::kSpeculativeNumberSubtract:  // Fall through.
    case IrOpcode::kSpeculativeSafeIntegerSubtract:
    case IrOpcode::kNumberSubtract:
      return machine()->Int32Sub();
    case IrOpcode::kSpeculativeNumberMultiply:
    case IrOpcode::kNumberMultiply:
      return machine()->Int32Mul();
    case IrOpcode::kSpeculativeNumberDivide:
    case IrOpcode::kNumberDivide:
      return machine()->Int32Div();
    case IrOpcode::kSpeculativeNumberModulus:
    case IrOpcode::kNumberModulus:
      return machine()->Int32Mod();
    case IrOpcode::kSpeculativeNumberBitwiseOr:  // Fall through.
    case IrOpcode::kNumberBitwiseOr:
      return machine()->Word32Or();
    case IrOpcode::kSpeculativeNumberBitwiseXor:  // Fall through.
    case IrOpcode::kNumberBitwiseXor:
      return machine()->Word32Xor();
    case IrOpcode::kSpeculativeNumberBitwiseAnd:  // Fall through.
    case IrOpcode::kNumberBitwiseAnd:
      return machine()->Word32And();
    case IrOpcode::kNumberEqual:
    case IrOpcode::kSpeculativeNumberEqual:
      return machine()->Word32Equal();
    case IrOpcode::kNumberLessThan:
    case IrOpcode::kSpeculativeNumberLessThan:
      return machine()->Int32LessThan();
    case IrOpcode::kNumberLessThanOrEqual:
    case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      return machine()->Int32LessThanOrEqual();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::Int32OverflowOperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeSafeIntegerAdd:
      return simplified()->CheckedInt32Add();
    case IrOpcode::kSpeculativeSafeIntegerSubtract:
      return simplified()->CheckedInt32Sub();
    case IrOpcode::kSpeculativeNumberDivide:
      return simplified()->CheckedInt32Div();
    case IrOpcode::kSpeculativeNumberModulus:
      return simplified()->CheckedInt32Mod();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::Int64OperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeNumberAdd:  // Fall through.
    case IrOpcode::kSpeculativeSafeIntegerAdd:
    case IrOpcode::kNumberAdd:
    case IrOpcode::kSpeculativeBigIntAdd:
      return machine()->Int64Add();
    case IrOpcode::kSpeculativeNumberSubtract:  // Fall through.
    case IrOpcode::kSpeculativeSafeIntegerSubtract:
    case IrOpcode::kNumberSubtract:
    case IrOpcode::kSpeculativeBigIntSubtract:
      return machine()->Int64Sub();
    case IrOpcode::kSpeculativeBigIntMultiply:
      return machine()->Int64Mul();
    case IrOpcode::kSpeculativeBigIntBitwiseAnd:
      return machine()->Word64And();
    case IrOpcode::kSpeculativeBigIntBitwiseOr:
      return machine()->Word64Or();
    case IrOpcode::kSpeculativeBigIntBitwiseXor:
      return machine()->Word64Xor();
    case IrOpcode::kSpeculativeBigIntEqual:
      return machine()->Word64Equal();
    case IrOpcode::kSpeculativeBigIntLessThan:
      return machine()->Int64LessThan();
    case IrOpcode::kSpeculativeBigIntLessThanOrEqual:
      return machine()->Int64LessThanOrEqual();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::Int64OverflowOperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeBigIntAdd:
      return simplified()->CheckedInt64Add();
    case IrOpcode::kSpeculativeBigIntSubtract:
      return simplified()->CheckedInt64Sub();
    case IrOpcode::kSpeculativeBigIntMultiply:
      return simplified()->CheckedInt64Mul();
    case IrOpcode::kSpeculativeBigIntDivide:
      return simplified()->CheckedInt64Div();
    case IrOpcode::kSpeculativeBigIntModulus:
      return simplified()->CheckedInt64Mod();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::BigIntOperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeBigIntAdd:
      return simplified()->BigIntAdd();
    case IrOpcode::kSpeculativeBigIntSubtract:
      return simplified()->BigIntSubtract();
    case IrOpcode::kSpeculativeBigIntMultiply:
      return simplified()->BigIntMultiply();
    case IrOpcode::kSpeculativeBigIntDivide:
      return simplified()->BigIntDivide();
    case IrOpcode::kSpeculativeBigIntModulus:
      return simplified()->BigIntModulus();
    case IrOpcode::kSpeculativeBigIntBitwiseAnd:
      return simplified()->BigIntBitwiseAnd();
    case IrOpcode::kSpeculativeBigIntBitwiseOr:
      return simplified()->BigIntBitwiseOr();
    case IrOpcode::kSpeculativeBigIntBitwiseXor:
      return simplified()->BigIntBitwiseXor();
    case IrOpcode::kSpeculativeBigIntShiftLeft:
      return simplified()->BigIntShiftLeft();
    case IrOpcode::kSpeculativeBigIntShiftRight:
      return simplified()->BigIntShiftRight();
    case IrOpcode::kSpeculativeBigIntEqual:
      return simplified()->BigIntEqual();
    case IrOpcode::kSpeculativeBigIntLessThan:
      return simplified()->BigIntLessThan();
    case IrOpcode::kSpeculativeBigIntLessThanOrEqual:
      return simplified()->BigIntLessThanOrEqual();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::TaggedSignedOperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeNumberLessThan:
      return (COMPRESS_POINTERS_BOOL || machine()->Is32())
                 ? machine()->Int32LessThan()
                 : machine()->Int64LessThan();
    case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      return (COMPRESS_POINTERS_BOOL || machine()->Is32())
                 ? machine()->Int32LessThanOrEqual()
                 : machine()->Int64LessThanOrEqual();
    case IrOpcode::kSpeculativeNumberEqual:
      return (COMPRESS_POINTERS_BOOL || machine()->Is32())
                 ? machine()->Word32Equal()
                 : machine()->Word64Equal();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::Uint32OperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kNumberAdd:
      return machine()->Int32Add();
    case IrOpcode::kNumberSubtract:
      return machine()->Int32Sub();
    case IrOpcode::kSpeculativeNumberMultiply:
    case IrOpcode::kNumberMultiply:
      return machine()->Int32Mul();
    case IrOpcode::kSpeculativeNumberDivide:
    case IrOpcode::kNumberDivide:
      return machine()->Uint32Div();
    case IrOpcode::kSpeculativeNumberModulus:
    case IrOpcode::kNumberModulus:
      return machine()->Uint32Mod();
    case IrOpcode::kNumberEqual:
    case IrOpcode::kSpeculativeNumberEqual:
      return machine()->Word32Equal();
    case IrOpcode::kNumberLessThan:
    case IrOpcode::kSpeculativeNumberLessThan:
      return machine()->Uint32LessThan();
    case IrOpcode::kNumberLessThanOrEqual:
    case IrOpcode::kSpeculativeNumberLessThanOrEqual:
      return machine()->Uint32LessThanOrEqual();
    case IrOpcode::kNumberClz32:
      return machine()->Word32Clz();
    case IrOpcode::kNumberImul:
      return machine()->Int32Mul();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::Uint32OverflowOperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeNumberDivide:
      return simplified()->CheckedUint32Div();
    case IrOpcode::kSpeculativeNumberModulus:
      return simplified()->CheckedUint32Mod();
    default:
      UNREACHABLE();
  }
}

const Operator* RepresentationChanger::Float64OperatorFor(
    IrOpcode::Value opcode) {
  switch (opcode) {
    case IrOpcode::kSpeculativeNumberAdd:
    case IrOpcode::kSpeculativeSafeIntegerAdd:
    case IrOpcode::kNumberAdd:
      return machine()->Float64Add();
    case IrOpcode::kSpeculativeNumberSubtract:
    c
```