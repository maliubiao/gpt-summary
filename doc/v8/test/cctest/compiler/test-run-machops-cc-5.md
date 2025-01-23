Response:
The user wants to understand the functionality of the C++ code snippet provided from `v8/test/cctest/compiler/test-run-machops.cc`.

Here's a breakdown of how to address the request:

1. **Identify the Core Functionality:** The code consists of multiple `TEST` functions using `RawMachineAssemblerTester`. This suggests that the file is testing the functionality of low-level machine operations within V8's compiler. These tests seem to directly manipulate the machine code generation.

2. **Analyze Individual Tests:** Each `TEST` function seems to focus on a specific machine operation or a combination of them. Look for patterns like:
    * Setting up input values (constants, memory locations).
    * Using `RawMachineAssemblerTester` to build a small code snippet.
    * Performing operations like addition, comparison, loading, storing, branching.
    * Calling the generated code using `m.Call()`.
    * Asserting the results using `CHECK_EQ`.

3. **Check for `.tq` Extension:**  The prompt explicitly asks if the file ends with `.tq`. This is not the case here, so we can rule out it being a Torque file.

4. **Relate to JavaScript Functionality:** While these are low-level tests, they underpin JavaScript's behavior. Think about which JavaScript operations rely on these machine-level operations (e.g., arithmetic, comparisons, type conversions).

5. **Provide JavaScript Examples:** For relevant tests, create simple JavaScript snippets that would trigger the corresponding machine operations being tested.

6. **Demonstrate Code Logic and Assumptions:** For tests with conditional logic (like `RunBranchPhi`), show how different inputs could lead to different execution paths and outputs.

7. **Identify Common Programming Errors:**  Connect the tested operations to common programming errors. For instance, overflow checks relate to potential integer overflow issues in JavaScript (though JavaScript handles this differently than C++).

8. **Address the "Part X of Y" Instruction:**  Acknowledge that this is part 6 of 8 and provide a summary of the functionalities covered in this specific part. Avoid speculating on what might be in the other parts.

9. **Structure the Output:** Organize the information clearly, using headings and bullet points for readability.
```cpp
buffer = 0.1;
  double dconstant = 99.997;
  DirectHandle<String> rexpected =
      CcTest::i_isolate()->factory()->InternalizeUtf8String("AD");
  Tagged<String> rbuffer;

  RawMachineLabel blocka, blockb, mid, blockd, blocke, end;
  Node* d1 = m.Float64Constant(dconstant);
  Node* d2 = m.Float64Constant(0 - dconstant);
  Node* r1 = m.StringConstant("AD");
  Node* r2 = m.StringConstant("BD");
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&mid);
  m.Bind(&blockb);
  m.Goto(&mid);
  m.Bind(&mid);
  Node* dphi1 = m.Phi(MachineRepresentation::kFloat64, d2, d1);
  Node* rphi1 = m.Phi(MachineRepresentation::kTagged, r2, r1);
  m.Branch(m.Int32Constant(0), &blockd, &blocke);

  m.Bind(&blockd);
  m.Goto(&end);
  m.Bind(&blocke);
  m.Goto(&end);
  m.Bind(&end);
  Node* dphi2 = m.Phi(MachineRepresentation::kFloat64, d1, dphi1);
  Node* rphi2 = m.Phi(MachineRepresentation::kTagged, r1, rphi1);

  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&dbuffer),
          m.Int32Constant(0), dphi2, kNoWriteBarrier);
  if (COMPRESS_POINTERS_BOOL) {
    // Since |buffer| is located off-heap, use full pointer store.
    m.Store(MachineType::PointerRepresentation(), m.PointerConstant(&rbuffer),
            m.Int32Constant(0), m.BitcastTaggedToWord(rphi2), kNoWriteBarrier);
  } else {
    m.Store(MachineRepresentation::kTagged, m.PointerConstant(&rbuffer),
            m.Int32Constant(0), rphi2, kNoWriteBarrier);
  }
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK_EQ(dconstant, dbuffer);
  CHECK(Object::SameValue(*rexpected, rbuffer));
}

TEST(RunDoubleLoopPhi) {
  RawMachineAssemblerTester<int32_t> m;
  RawMachineLabel header, body, end;

  int magic = 99773;
  double buffer = 0.99;
  double dconstant = 777.1;

  Node* zero = m.Int32Constant(0);
  Node* dk = m.Float64Constant(dconstant);

  m.Goto(&header);
  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat64, dk, dk);
  phi->ReplaceInput(1, phi);
  m.Branch(zero, &body, &end);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&end);
  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&buffer),
          m.Int32Constant(0), phi, kNoWriteBarrier);
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
}

TEST(RunCountToTenAccRaw) {
  RawMachineAssemblerTester<int32_t> m;

  Node* zero = m.Int32Constant(0);
  Node* ten = m.Int32Constant(10);
  Node* one = m.Int32Constant(1);

  RawMachineLabel header, body, body_cont, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* i = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* j = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Goto(&body);

  m.Bind(&body);
  Node* next_i = m.Int32Add(i, one);
  Node* next_j = m.Int32Add(j, one);
  m.Branch(m.Word32Equal(next_i, ten), &end, &body_cont);

  m.Bind(&body_cont);
  i->ReplaceInput(1, next_i);
  j->ReplaceInput(1, next_j);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(ten);

  CHECK_EQ(10, m.Call());
}

TEST(RunCountToTenAccRaw2) {
  RawMachineAssemblerTester<int32_t> m;

  Node* zero = m.Int32Constant(0);
  Node* ten = m.Int32Constant(10);
  Node* one = m.Int32Constant(1);

  RawMachineLabel header, body, body_cont, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* i = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* j = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* k = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Goto(&body);

  m.Bind(&body);
  Node* next_i = m.Int32Add(i, one);
  Node* next_j = m.Int32Add(j, one);
  Node* next_k = m.Int32Add(j, one);
  m.Branch(m.Word32Equal(next_i, ten), &end, &body_cont);

  m.Bind(&body_cont);
  i->ReplaceInput(1, next_i);
  j->ReplaceInput(1, next_j);
  k->ReplaceInput(1, next_k);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(ten);

  CHECK_EQ(10, m.Call());
}

TEST(RunAddTree) {
  RawMachineAssemblerTester<int32_t> m;
  int32_t inputs[] = {11, 12, 13, 14, 15, 16, 17, 18};

  Node* base = m.PointerConstant(inputs);
  Node* n0 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(0 * sizeof(int32_t)));
  Node* n1 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(1 * sizeof(int32_t)));
  Node* n2 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(2 * sizeof(int32_t)));
  Node* n3 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(3 * sizeof(int32_t)));
  Node* n4 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(4 * sizeof(int32_t)));
  Node* n5 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(5 * sizeof(int32_t)));
  Node* n6 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(6 * sizeof(int32_t)));
  Node* n7 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(7 * sizeof(int32_t)));

  Node* i1 = m.Int32Add(n0, n1);
  Node* i2 = m.Int32Add(n2, n3);
  Node* i3 = m.Int32Add(n4, n5);
  Node* i4 = m.Int32Add(n6, n7);

  Node* i5 = m.Int32Add(i1, i2);
  Node* i6 = m.Int32Add(i3, i4);

  Node* i7 = m.Int32Add(i5, i6);

  m.Return(i7);

  CHECK_EQ(116, m.Call());
}

static const int kFloat64CompareHelperTestCases = 15;
static const int kFloat64CompareHelperNodeType = 4;

static int Float64CompareHelper(RawMachineAssemblerTester<int32_t>* m,
                                int test_case, int node_type, double x,
                                double y) {
  static double buffer[2];
  buffer[0] = x;
  buffer[1] = y;
  CHECK(0 <= test_case && test_case < kFloat64CompareHelperTestCases);
  CHECK(0 <= node_type && node_type < kFloat64CompareHelperNodeType);
  CHECK(x < y);
  bool load_a = node_type / 2 == 1;
  bool load_b = node_type % 2 == 1;
  Node* a =
      load_a ? m->Load(MachineType::Float64(), m->PointerConstant(&buffer[0]))
             : m->Float64Constant(x);
  Node* b =
      load_b ? m->Load(MachineType::Float64(), m->PointerConstant(&buffer[1]))
             : m->Float64Constant(y);
  Node* cmp = nullptr;
  bool expected = false;
  switch (test_case) {
    // Equal tests.
    case 0:
      cmp = m->Float64Equal(a, b);
      expected = false;
      break;
    case 1:
      cmp = m->Float64Equal(a, a);
      expected = true;
      break;
    // LessThan tests.
    case 2:
      cmp = m->Float64LessThan(a, b);
      expected = true;
      break;
    case 3:
      cmp = m->Float64LessThan(b, a);
      expected = false;
      break;
    case 4:
      cmp = m->Float64LessThan(a, a);
      expected = false;
      break;
    // LessThanOrEqual tests.
    case 5:
      cmp = m->Float64LessThanOrEqual(a, b);
      expected = true;
      break;
    case 6:
      cmp = m->Float64LessThanOrEqual(b, a);
      expected = false;
      break;
    case 7:
      cmp = m->Float64LessThanOrEqual(a, a);
      expected = true;
      break;
    // NotEqual tests.
    case 8:
      cmp = m->Float64NotEqual(a, b);
      expected = true;
      break;
    case 9:
      cmp = m->Float64NotEqual(b, a);
      expected = true;
      break;
    case 10:
      cmp = m->Float64NotEqual(a, a);
      expected = false;
      break;
    // GreaterThan tests.
    case 11:
      cmp = m->Float64GreaterThan(a, a);
      expected = false;
      break;
    case 12:
      cmp = m->Float64GreaterThan(a, b);
      expected = false;
      break;
    // GreaterThanOrEqual tests.
    case 13:
      cmp = m->Float64GreaterThanOrEqual(a, a);
      expected = true;
      break;
    case 14:
      cmp = m->Float64GreaterThanOrEqual(b, a);
      expected = true;
      break;
    default:
      UNREACHABLE();
  }
  m->Return(cmp);
  return expected;
}

TEST(RunFloat64Compare) {
  double inf = V8_INFINITY;
  // All pairs (a1, a2) are of the form a1 < a2.
  double inputs[] = {0.0,  1.0,  -1.0, 0.22, -1.22, 0.22,
                     -inf, 0.22, 0.22, inf,  -inf,  inf};

  for (int test = 0; test < kFloat64CompareHelperTestCases; test++) {
    for (int node_type = 0; node_type < kFloat64CompareHelperNodeType;
         node_type++) {
      for (size_t input = 0; input < arraysize(inputs); input += 2) {
        RawMachineAssemblerTester<int32_t> m;
        int expected = Float64CompareHelper(&m, test, node_type, inputs[input],
                                            inputs[input + 1]);
        CHECK_EQ(expected, m.Call());
      }
    }
  }
}

TEST(RunFloat64UnorderedCompare) {
  RawMachineAssemblerTester<int32_t> m;

  const Operator* operators[] = {m.machine()->Float64Equal(),
                                 m.machine()->Float64LessThan(),
                                 m.machine()->Float64LessThanOrEqual()};

  double nan = std::numeric_limits<double>::quiet_NaN();

  FOR_FLOAT64_INPUTS(i) {
    for (size_t o = 0; o < arraysize(operators); ++o) {
      for (int j = 0; j < 2; j++) {
        RawMachineAssemblerTester<int32_t> t;
        Node* a = t.Float64Constant(i);
        Node* b = t.Float64Constant(nan);
        if (j == 1) std::swap(a, b);
        t.Return(t.AddNode(operators[o], a, b));
        CHECK_EQ(0, t.Call());
      }
    }
  }
}

TEST(RunFloat64Equal) {
  double input_a = 0.0;
  double input_b = 0.0;

  RawMachineAssemblerTester<int32_t> m;
  Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
  Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());
  m.Return(m.Float64Equal(a, b));

  CompareWrapper cmp(IrOpcode::kFloat64Equal);
  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      input_a = pl;
      input_b = pr;
      int32_t expected = cmp.Float64Compare(input_a, input_b) ? 1 : 0;
      CHECK_EQ(expected, m.Call());
    }
  }
}

TEST(RunFloat64LessThan) {
  double input_a = 0.0;
  double input_b = 0.0;

  RawMachineAssemblerTester<int32_t> m;
  Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
  Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());
  m.Return(m.Float64LessThan(a, b));

  CompareWrapper cmp(IrOpcode::kFloat64LessThan);
  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      input_a = pl;
      input_b = pr;
      int32_t expected = cmp.Float64Compare(input_a, input_b) ? 1 : 0;
      CHECK_EQ(expected, m.Call());
    }
  }
}

static void IntPtrCompare(intptr_t left, intptr_t right) {
  for (int test = 0; test < 7; test++) {
    RawMachineAssemblerTester<bool> m(MachineType::Pointer(),
                                      MachineType::Pointer());
    Node* p0 = m.Parameter(0);
    Node* p1 = m.Parameter(1);
    Node* res = nullptr;
    bool expected = false;
    switch (test) {
      case 0:
        res = m.IntPtrLessThan(p0, p1);
        expected = true;
        break;
      case 1:
        res = m.IntPtrLessThanOrEqual(p0, p1);
        expected = true;
        break;
      case 2:
        res = m.IntPtrEqual(p0, p1);
        expected = false;
        break;
      case 3:
        res = m.IntPtrGreaterThanOrEqual(p0, p1);
        expected = false;
        break;
      case 4:
        res = m.IntPtrGreaterThan(p0, p1);
        expected = false;
        break;
      case 5:
        res = m.IntPtrEqual(p0, p0);
        expected = true;
        break;
      case 6:
        res = m.IntPtrNotEqual(p0, p1);
        expected = true;
        break;
      default:
        UNREACHABLE();
    }
    m.Return(res);
    CHECK_EQ(expected, m.Call(reinterpret_cast<int32_t*>(left),
                              reinterpret_cast<int32_t*>(right)));
  }
}

TEST(RunIntPtrCompare) {
  intptr_t min = std::numeric_limits<intptr_t>::min();
  intptr_t max = std::numeric_limits<intptr_t>::max();
  // An ascending chain of intptr_t
  intptr_t inputs[] = {min, min / 2, -1, 0, 1, max / 2, max};
  for (size_t i = 0; i < arraysize(inputs) - 1; i++) {
    IntPtrCompare(inputs[i], inputs[i + 1]);
  }
}

TEST(RunTestIntPtrArithmetic) {
  static const int kInputSize = 10;
  int32_t inputs[kInputSize];
  int32_t outputs[kInputSize];
  for (int i = 0; i < kInputSize; i++) {
    inputs[i] = i;
    outputs[i] = -1;
  }
  RawMachineAssemblerTester<int32_t*> m;
  Node* input = m.PointerConstant(&inputs[0]);
  Node* output = m.PointerConstant(&outputs[kInputSize - 1]);
  Node* elem_size = m.IntPtrConstant(sizeof(inputs[0]));
  for (int i = 0; i < kInputSize; i++) {
    m.Store(MachineRepresentation::kWord32, output,
            m.Load(MachineType::Int32(), input), kNoWriteBarrier);
    input = m.IntPtrAdd(input, elem_size);
    output = m.IntPtrSub(output, elem_size);
  }
  m.Return(input);
  CHECK_EQ(&inputs[kInputSize], m.Call());
  for (int i = 0; i < kInputSize; i++) {
    CHECK_EQ(i, inputs[i]);
    CHECK_EQ(kInputSize - i - 1, outputs[i]);
  }
}

TEST(RunSpillLotsOfThings) {
  static const int kInputSize = 1000;
  RawMachineAssemblerTester<int32_t> m;
  Node* accs[kInputSize];
  int32_t outputs[kInputSize];
  Node* one = m.Int32Constant(1);
  Node* acc = one;
  for (int i = 0; i < kInputSize; i++) {
    acc = m.Int32Add(acc, one);
    accs[i] = acc;
  }
  for (int i = 0; i < kInputSize; i++) {
    m.StoreToPointer(&outputs[i], MachineRepresentation::kWord32, accs[i]);
  }
  m.Return(one);
  m.Call();
  for (int i = 0; i < kInputSize; i++) {
    CHECK_EQ(outputs[i], i + 2);
  }
}

TEST(RunSpillConstantsAndParameters) {
  static const int kInputSize = 1000;
  static const int32_t kBase = 987;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  int32_t outputs[kInputSize];
  Node* csts[kInputSize];
  Node* accs[kInputSize];
  Node* acc = m.Int32Constant(0);
  for (int i = 0; i < kInputSize; i++) {
    csts[i] = m.Int32Constant(base::AddWithWraparound(kBase, i));
  }
  for (int i = 0; i < kInputSize; i++) {
    acc = m.Int32Add(acc, csts[i]);
    accs[i] = acc;
  }
  for (int i = 0; i < kInputSize; i++) {
    m.StoreToPointer(&outputs[i], MachineRepresentation::kWord32, accs[i]);
  }
  m.Return(m.Int32Add(acc, m.Int32Add(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = base::AddWithWraparound(i, j);
      for (int k = 0; k < kInputSize; k++) {
        expected = base::AddWithWraparound(expected, kBase + k);
      }
      CHECK_EQ(expected, m.Call(i, j));
      expected = 0;
      for (int k = 0; k < kInputSize; k++) {
        expected += kBase + k;
        CHECK_EQ(expected, outputs[k]);
      }
    }
  }
}

TEST(RunNewSpaceConstantsInPhi) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());

  Isolate* isolate = CcTest::i_isolate();
  Handle<HeapNumber> true_val = isolate->factory()->NewHeapNumber(11.2);
  Handle<HeapNumber> false_val = isolate->factory()->NewHeapNumber(11.3);
  Node* true_node = m.HeapConstant(true_val);
  Node* false_node = m.HeapConstant(false_val);

  RawMachineLabel blocka, blockb, end;
  m.Branch(m.Parameter(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);

  m.Bind(&end);
  Node* phi = m.Phi(MachineRepresentation::kTagged, true_node, false_node);
  m.Return(phi);

  CHECK_EQ(*false_val, m.Call(0));
  CHECK_EQ(*true_val, m.Call(1));
}

TEST(RunInt32AddWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32AddWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}

TEST(RunInt32AddWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32AddWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32AddWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32AddWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}

TEST(RunInt32AddWithOverflowInBranchP) {
  int constant = 911777;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32AddWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, add);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, add);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedAddOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}

TEST(RunInt32SubWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32SubWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}

TEST(RunInt32SubWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32SubWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32SubWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow32(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32SubWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedSubOverflow
### 提示词
```
这是目录为v8/test/cctest/compiler/test-run-machops.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-run-machops.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
buffer = 0.1;
  double dconstant = 99.997;
  DirectHandle<String> rexpected =
      CcTest::i_isolate()->factory()->InternalizeUtf8String("AD");
  Tagged<String> rbuffer;

  RawMachineLabel blocka, blockb, mid, blockd, blocke, end;
  Node* d1 = m.Float64Constant(dconstant);
  Node* d2 = m.Float64Constant(0 - dconstant);
  Node* r1 = m.StringConstant("AD");
  Node* r2 = m.StringConstant("BD");
  m.Branch(m.Int32Constant(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&mid);
  m.Bind(&blockb);
  m.Goto(&mid);
  m.Bind(&mid);
  Node* dphi1 = m.Phi(MachineRepresentation::kFloat64, d2, d1);
  Node* rphi1 = m.Phi(MachineRepresentation::kTagged, r2, r1);
  m.Branch(m.Int32Constant(0), &blockd, &blocke);

  m.Bind(&blockd);
  m.Goto(&end);
  m.Bind(&blocke);
  m.Goto(&end);
  m.Bind(&end);
  Node* dphi2 = m.Phi(MachineRepresentation::kFloat64, d1, dphi1);
  Node* rphi2 = m.Phi(MachineRepresentation::kTagged, r1, rphi1);

  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&dbuffer),
          m.Int32Constant(0), dphi2, kNoWriteBarrier);
  if (COMPRESS_POINTERS_BOOL) {
    // Since |buffer| is located off-heap, use full pointer store.
    m.Store(MachineType::PointerRepresentation(), m.PointerConstant(&rbuffer),
            m.Int32Constant(0), m.BitcastTaggedToWord(rphi2), kNoWriteBarrier);
  } else {
    m.Store(MachineRepresentation::kTagged, m.PointerConstant(&rbuffer),
            m.Int32Constant(0), rphi2, kNoWriteBarrier);
  }
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
  CHECK_EQ(dconstant, dbuffer);
  CHECK(Object::SameValue(*rexpected, rbuffer));
}


TEST(RunDoubleLoopPhi) {
  RawMachineAssemblerTester<int32_t> m;
  RawMachineLabel header, body, end;

  int magic = 99773;
  double buffer = 0.99;
  double dconstant = 777.1;

  Node* zero = m.Int32Constant(0);
  Node* dk = m.Float64Constant(dconstant);

  m.Goto(&header);
  m.Bind(&header);
  Node* phi = m.Phi(MachineRepresentation::kFloat64, dk, dk);
  phi->ReplaceInput(1, phi);
  m.Branch(zero, &body, &end);
  m.Bind(&body);
  m.Goto(&header);
  m.Bind(&end);
  m.Store(MachineRepresentation::kFloat64, m.PointerConstant(&buffer),
          m.Int32Constant(0), phi, kNoWriteBarrier);
  m.Return(m.Int32Constant(magic));

  CHECK_EQ(magic, m.Call());
}


TEST(RunCountToTenAccRaw) {
  RawMachineAssemblerTester<int32_t> m;

  Node* zero = m.Int32Constant(0);
  Node* ten = m.Int32Constant(10);
  Node* one = m.Int32Constant(1);

  RawMachineLabel header, body, body_cont, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* i = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* j = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Goto(&body);

  m.Bind(&body);
  Node* next_i = m.Int32Add(i, one);
  Node* next_j = m.Int32Add(j, one);
  m.Branch(m.Word32Equal(next_i, ten), &end, &body_cont);

  m.Bind(&body_cont);
  i->ReplaceInput(1, next_i);
  j->ReplaceInput(1, next_j);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(ten);

  CHECK_EQ(10, m.Call());
}


TEST(RunCountToTenAccRaw2) {
  RawMachineAssemblerTester<int32_t> m;

  Node* zero = m.Int32Constant(0);
  Node* ten = m.Int32Constant(10);
  Node* one = m.Int32Constant(1);

  RawMachineLabel header, body, body_cont, end;

  m.Goto(&header);

  m.Bind(&header);
  Node* i = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* j = m.Phi(MachineRepresentation::kWord32, zero, zero);
  Node* k = m.Phi(MachineRepresentation::kWord32, zero, zero);
  m.Goto(&body);

  m.Bind(&body);
  Node* next_i = m.Int32Add(i, one);
  Node* next_j = m.Int32Add(j, one);
  Node* next_k = m.Int32Add(j, one);
  m.Branch(m.Word32Equal(next_i, ten), &end, &body_cont);

  m.Bind(&body_cont);
  i->ReplaceInput(1, next_i);
  j->ReplaceInput(1, next_j);
  k->ReplaceInput(1, next_k);
  m.Goto(&header);

  m.Bind(&end);
  m.Return(ten);

  CHECK_EQ(10, m.Call());
}


TEST(RunAddTree) {
  RawMachineAssemblerTester<int32_t> m;
  int32_t inputs[] = {11, 12, 13, 14, 15, 16, 17, 18};

  Node* base = m.PointerConstant(inputs);
  Node* n0 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(0 * sizeof(int32_t)));
  Node* n1 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(1 * sizeof(int32_t)));
  Node* n2 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(2 * sizeof(int32_t)));
  Node* n3 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(3 * sizeof(int32_t)));
  Node* n4 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(4 * sizeof(int32_t)));
  Node* n5 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(5 * sizeof(int32_t)));
  Node* n6 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(6 * sizeof(int32_t)));
  Node* n7 =
      m.Load(MachineType::Int32(), base, m.Int32Constant(7 * sizeof(int32_t)));

  Node* i1 = m.Int32Add(n0, n1);
  Node* i2 = m.Int32Add(n2, n3);
  Node* i3 = m.Int32Add(n4, n5);
  Node* i4 = m.Int32Add(n6, n7);

  Node* i5 = m.Int32Add(i1, i2);
  Node* i6 = m.Int32Add(i3, i4);

  Node* i7 = m.Int32Add(i5, i6);

  m.Return(i7);

  CHECK_EQ(116, m.Call());
}


static const int kFloat64CompareHelperTestCases = 15;
static const int kFloat64CompareHelperNodeType = 4;

static int Float64CompareHelper(RawMachineAssemblerTester<int32_t>* m,
                                int test_case, int node_type, double x,
                                double y) {
  static double buffer[2];
  buffer[0] = x;
  buffer[1] = y;
  CHECK(0 <= test_case && test_case < kFloat64CompareHelperTestCases);
  CHECK(0 <= node_type && node_type < kFloat64CompareHelperNodeType);
  CHECK(x < y);
  bool load_a = node_type / 2 == 1;
  bool load_b = node_type % 2 == 1;
  Node* a =
      load_a ? m->Load(MachineType::Float64(), m->PointerConstant(&buffer[0]))
             : m->Float64Constant(x);
  Node* b =
      load_b ? m->Load(MachineType::Float64(), m->PointerConstant(&buffer[1]))
             : m->Float64Constant(y);
  Node* cmp = nullptr;
  bool expected = false;
  switch (test_case) {
    // Equal tests.
    case 0:
      cmp = m->Float64Equal(a, b);
      expected = false;
      break;
    case 1:
      cmp = m->Float64Equal(a, a);
      expected = true;
      break;
    // LessThan tests.
    case 2:
      cmp = m->Float64LessThan(a, b);
      expected = true;
      break;
    case 3:
      cmp = m->Float64LessThan(b, a);
      expected = false;
      break;
    case 4:
      cmp = m->Float64LessThan(a, a);
      expected = false;
      break;
    // LessThanOrEqual tests.
    case 5:
      cmp = m->Float64LessThanOrEqual(a, b);
      expected = true;
      break;
    case 6:
      cmp = m->Float64LessThanOrEqual(b, a);
      expected = false;
      break;
    case 7:
      cmp = m->Float64LessThanOrEqual(a, a);
      expected = true;
      break;
    // NotEqual tests.
    case 8:
      cmp = m->Float64NotEqual(a, b);
      expected = true;
      break;
    case 9:
      cmp = m->Float64NotEqual(b, a);
      expected = true;
      break;
    case 10:
      cmp = m->Float64NotEqual(a, a);
      expected = false;
      break;
    // GreaterThan tests.
    case 11:
      cmp = m->Float64GreaterThan(a, a);
      expected = false;
      break;
    case 12:
      cmp = m->Float64GreaterThan(a, b);
      expected = false;
      break;
    // GreaterThanOrEqual tests.
    case 13:
      cmp = m->Float64GreaterThanOrEqual(a, a);
      expected = true;
      break;
    case 14:
      cmp = m->Float64GreaterThanOrEqual(b, a);
      expected = true;
      break;
    default:
      UNREACHABLE();
  }
  m->Return(cmp);
  return expected;
}


TEST(RunFloat64Compare) {
  double inf = V8_INFINITY;
  // All pairs (a1, a2) are of the form a1 < a2.
  double inputs[] = {0.0,  1.0,  -1.0, 0.22, -1.22, 0.22,
                     -inf, 0.22, 0.22, inf,  -inf,  inf};

  for (int test = 0; test < kFloat64CompareHelperTestCases; test++) {
    for (int node_type = 0; node_type < kFloat64CompareHelperNodeType;
         node_type++) {
      for (size_t input = 0; input < arraysize(inputs); input += 2) {
        RawMachineAssemblerTester<int32_t> m;
        int expected = Float64CompareHelper(&m, test, node_type, inputs[input],
                                            inputs[input + 1]);
        CHECK_EQ(expected, m.Call());
      }
    }
  }
}


TEST(RunFloat64UnorderedCompare) {
  RawMachineAssemblerTester<int32_t> m;

  const Operator* operators[] = {m.machine()->Float64Equal(),
                                 m.machine()->Float64LessThan(),
                                 m.machine()->Float64LessThanOrEqual()};

  double nan = std::numeric_limits<double>::quiet_NaN();

  FOR_FLOAT64_INPUTS(i) {
    for (size_t o = 0; o < arraysize(operators); ++o) {
      for (int j = 0; j < 2; j++) {
        RawMachineAssemblerTester<int32_t> t;
        Node* a = t.Float64Constant(i);
        Node* b = t.Float64Constant(nan);
        if (j == 1) std::swap(a, b);
        t.Return(t.AddNode(operators[o], a, b));
        CHECK_EQ(0, t.Call());
      }
    }
  }
}


TEST(RunFloat64Equal) {
  double input_a = 0.0;
  double input_b = 0.0;

  RawMachineAssemblerTester<int32_t> m;
  Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
  Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());
  m.Return(m.Float64Equal(a, b));

  CompareWrapper cmp(IrOpcode::kFloat64Equal);
  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      input_a = pl;
      input_b = pr;
      int32_t expected = cmp.Float64Compare(input_a, input_b) ? 1 : 0;
      CHECK_EQ(expected, m.Call());
    }
  }
}


TEST(RunFloat64LessThan) {
  double input_a = 0.0;
  double input_b = 0.0;

  RawMachineAssemblerTester<int32_t> m;
  Node* a = m.LoadFromPointer(&input_a, MachineType::Float64());
  Node* b = m.LoadFromPointer(&input_b, MachineType::Float64());
  m.Return(m.Float64LessThan(a, b));

  CompareWrapper cmp(IrOpcode::kFloat64LessThan);
  FOR_FLOAT64_INPUTS(pl) {
    FOR_FLOAT64_INPUTS(pr) {
      input_a = pl;
      input_b = pr;
      int32_t expected = cmp.Float64Compare(input_a, input_b) ? 1 : 0;
      CHECK_EQ(expected, m.Call());
    }
  }
}


static void IntPtrCompare(intptr_t left, intptr_t right) {
  for (int test = 0; test < 7; test++) {
    RawMachineAssemblerTester<bool> m(MachineType::Pointer(),
                                      MachineType::Pointer());
    Node* p0 = m.Parameter(0);
    Node* p1 = m.Parameter(1);
    Node* res = nullptr;
    bool expected = false;
    switch (test) {
      case 0:
        res = m.IntPtrLessThan(p0, p1);
        expected = true;
        break;
      case 1:
        res = m.IntPtrLessThanOrEqual(p0, p1);
        expected = true;
        break;
      case 2:
        res = m.IntPtrEqual(p0, p1);
        expected = false;
        break;
      case 3:
        res = m.IntPtrGreaterThanOrEqual(p0, p1);
        expected = false;
        break;
      case 4:
        res = m.IntPtrGreaterThan(p0, p1);
        expected = false;
        break;
      case 5:
        res = m.IntPtrEqual(p0, p0);
        expected = true;
        break;
      case 6:
        res = m.IntPtrNotEqual(p0, p1);
        expected = true;
        break;
      default:
        UNREACHABLE();
    }
    m.Return(res);
    CHECK_EQ(expected, m.Call(reinterpret_cast<int32_t*>(left),
                              reinterpret_cast<int32_t*>(right)));
  }
}


TEST(RunIntPtrCompare) {
  intptr_t min = std::numeric_limits<intptr_t>::min();
  intptr_t max = std::numeric_limits<intptr_t>::max();
  // An ascending chain of intptr_t
  intptr_t inputs[] = {min, min / 2, -1, 0, 1, max / 2, max};
  for (size_t i = 0; i < arraysize(inputs) - 1; i++) {
    IntPtrCompare(inputs[i], inputs[i + 1]);
  }
}


TEST(RunTestIntPtrArithmetic) {
  static const int kInputSize = 10;
  int32_t inputs[kInputSize];
  int32_t outputs[kInputSize];
  for (int i = 0; i < kInputSize; i++) {
    inputs[i] = i;
    outputs[i] = -1;
  }
  RawMachineAssemblerTester<int32_t*> m;
  Node* input = m.PointerConstant(&inputs[0]);
  Node* output = m.PointerConstant(&outputs[kInputSize - 1]);
  Node* elem_size = m.IntPtrConstant(sizeof(inputs[0]));
  for (int i = 0; i < kInputSize; i++) {
    m.Store(MachineRepresentation::kWord32, output,
            m.Load(MachineType::Int32(), input), kNoWriteBarrier);
    input = m.IntPtrAdd(input, elem_size);
    output = m.IntPtrSub(output, elem_size);
  }
  m.Return(input);
  CHECK_EQ(&inputs[kInputSize], m.Call());
  for (int i = 0; i < kInputSize; i++) {
    CHECK_EQ(i, inputs[i]);
    CHECK_EQ(kInputSize - i - 1, outputs[i]);
  }
}


TEST(RunSpillLotsOfThings) {
  static const int kInputSize = 1000;
  RawMachineAssemblerTester<int32_t> m;
  Node* accs[kInputSize];
  int32_t outputs[kInputSize];
  Node* one = m.Int32Constant(1);
  Node* acc = one;
  for (int i = 0; i < kInputSize; i++) {
    acc = m.Int32Add(acc, one);
    accs[i] = acc;
  }
  for (int i = 0; i < kInputSize; i++) {
    m.StoreToPointer(&outputs[i], MachineRepresentation::kWord32, accs[i]);
  }
  m.Return(one);
  m.Call();
  for (int i = 0; i < kInputSize; i++) {
    CHECK_EQ(outputs[i], i + 2);
  }
}


TEST(RunSpillConstantsAndParameters) {
  static const int kInputSize = 1000;
  static const int32_t kBase = 987;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32(),
                                       MachineType::Int32());
  int32_t outputs[kInputSize];
  Node* csts[kInputSize];
  Node* accs[kInputSize];
  Node* acc = m.Int32Constant(0);
  for (int i = 0; i < kInputSize; i++) {
    csts[i] = m.Int32Constant(base::AddWithWraparound(kBase, i));
  }
  for (int i = 0; i < kInputSize; i++) {
    acc = m.Int32Add(acc, csts[i]);
    accs[i] = acc;
  }
  for (int i = 0; i < kInputSize; i++) {
    m.StoreToPointer(&outputs[i], MachineRepresentation::kWord32, accs[i]);
  }
  m.Return(m.Int32Add(acc, m.Int32Add(m.Parameter(0), m.Parameter(1))));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = base::AddWithWraparound(i, j);
      for (int k = 0; k < kInputSize; k++) {
        expected = base::AddWithWraparound(expected, kBase + k);
      }
      CHECK_EQ(expected, m.Call(i, j));
      expected = 0;
      for (int k = 0; k < kInputSize; k++) {
        expected += kBase + k;
        CHECK_EQ(expected, outputs[k]);
      }
    }
  }
}


TEST(RunNewSpaceConstantsInPhi) {
  RawMachineAssemblerTester<Tagged<Object>> m(MachineType::Int32());

  Isolate* isolate = CcTest::i_isolate();
  Handle<HeapNumber> true_val = isolate->factory()->NewHeapNumber(11.2);
  Handle<HeapNumber> false_val = isolate->factory()->NewHeapNumber(11.3);
  Node* true_node = m.HeapConstant(true_val);
  Node* false_node = m.HeapConstant(false_val);

  RawMachineLabel blocka, blockb, end;
  m.Branch(m.Parameter(0), &blocka, &blockb);
  m.Bind(&blocka);
  m.Goto(&end);
  m.Bind(&blockb);
  m.Goto(&end);

  m.Bind(&end);
  Node* phi = m.Phi(MachineRepresentation::kTagged, true_node, false_node);
  m.Return(phi);

  CHECK_EQ(*false_val, m.Call(0));
  CHECK_EQ(*true_val, m.Call(1));
}


TEST(RunInt32AddWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32AddWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32AddWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32AddWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32AddWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32AddWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedAddOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32AddWithOverflowInBranchP) {
  int constant = 911777;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32AddWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, add);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, add);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedAddOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}


TEST(RunInt32SubWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32SubWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32SubWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32SubWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32SubWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedSubOverflow32(j, i, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        CHECK_EQ(expected_val, actual_val);
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32SubWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedSubOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      CHECK_EQ(expected_val, actual_val);
    }
  }
}


TEST(RunInt32SubWithOverflowInBranchP) {
  int constant = 911999;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* sub = m.Int32SubWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, sub);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, sub);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedSubOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}

TEST(RunInt32MulWithOverflowP) {
  int32_t actual_val = -1;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32MulWithOverflow(bt.param0, bt.param1);
  Node* val = m.Projection(0, add);
  Node* ovf = m.Projection(1, add);
  m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
  bt.AddReturn(ovf);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected_val;
      int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, bt.call(i, j));
      if (!expected_ovf) {
        CHECK_EQ(expected_val, actual_val);
      }
    }
  }
}

TEST(RunInt32MulWithOverflowImm) {
  int32_t actual_val = -1, expected_val = 0;
  FOR_INT32_INPUTS(i) {
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32MulWithOverflow(m.Int32Constant(i), m.Parameter(0));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        if (!expected_ovf) {
          CHECK_EQ(expected_val, actual_val);
        }
      }
    }
    {
      RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
      Node* add = m.Int32MulWithOverflow(m.Parameter(0), m.Int32Constant(i));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      FOR_INT32_INPUTS(j) {
        int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
        CHECK_EQ(expected_ovf, m.Call(j));
        if (!expected_ovf) {
          CHECK_EQ(expected_val, actual_val);
        }
      }
    }
    FOR_INT32_INPUTS(j) {
      RawMachineAssemblerTester<int32_t> m;
      Node* add =
          m.Int32MulWithOverflow(m.Int32Constant(i), m.Int32Constant(j));
      Node* val = m.Projection(0, add);
      Node* ovf = m.Projection(1, add);
      m.StoreToPointer(&actual_val, MachineRepresentation::kWord32, val);
      m.Return(ovf);
      int expected_ovf = base::bits::SignedMulOverflow32(i, j, &expected_val);
      CHECK_EQ(expected_ovf, m.Call());
      if (!expected_ovf) {
        CHECK_EQ(expected_val, actual_val);
      }
    }
  }
}

TEST(RunInt32MulWithOverflowInBranchP) {
  int constant = 911777;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  Int32BinopTester bt(&m);
  Node* add = m.Int32MulWithOverflow(bt.param0, bt.param1);
  Node* ovf = m.Projection(1, add);
  m.Branch(ovf, &blocka, &blockb);
  m.Bind(&blocka);
  bt.AddReturn(m.Int32Constant(constant));
  m.Bind(&blockb);
  Node* val = m.Projection(0, add);
  bt.AddReturn(val);
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected;
      if (base::bits::SignedMulOverflow32(i, j, &expected)) expected = constant;
      CHECK_EQ(expected, bt.call(i, j));
    }
  }
}

TEST(RunWord64EqualInBranchP) {
  int64_t input;
  RawMachineLabel blocka, blockb;
  RawMachineAssemblerTester<int32_t> m;
  if (!m.machine()->Is64()) return;
  Node* value = m.LoadFromPointer(&input, MachineType::Int64());
  m.Branch(m.Word64Equal(value, m.Int64Constant(0)), &blocka, &blockb);
  m.Bind(&blocka);
  m.Return(m.Int32Constant(1));
  m.Bind(&blockb);
  m.Return(m.Int32Constant(2));
  input = int64_t{0};
  CHECK_EQ(1, m.Call());
  input = int64_t{1};
  CHECK_EQ(2, m.Call());
  input = int64_t{0x100000000};
  CHECK_EQ(2, m.Call());
}


TEST(RunChangeInt32ToInt64P) {
  if (kSystemPointerSize < 8) return;
  int64_t actual = -1;
  RawMachineAssemblerTester<int32_t> m(MachineType::Int32());
  m.StoreToPointer(&actual, MachineRepresentation::kWord64,
                   m.ChangeInt32ToInt64(m.Parameter(0)));
  m.Return(m.Int32Constant(0));
  FOR_INT32_INPUTS(i) {
    int64_t expected = i;
    CHECK_EQ(0, m.Call(i));
    CHECK_EQ(expected, actual);
  }
}


TEST(RunChangeUint32ToUint64P) {
  if (kSystemPointerSize < 8) return;
  int64_t actual = -1;
  RawMachineAssemblerTester<int32_t> m(MachineType::Uint32());
  m.StoreToPointer(&actual, MachineRepresentation::kWord64,
                   m.ChangeUint32ToUint64(m.Parameter(0)));
  m.Return(m.Int32Constant(0));
  FOR_UINT32_INPUTS(i) {
    int64_t expected = static_cast<uint64_t>(i);
    CHECK_EQ(0, m.Call(i));
    CHECK_EQ(expected, actual);
  }
}


TEST(RunTruncateInt64ToInt32P) {
  if (kSystemPointerSize < 8) return;
  int64_t expected = -1;
  RawMachineAssemblerTester<int32_t> m;
  m.Return(m.TruncateInt64ToInt32(
      m.LoadFromPointer(&expected, MachineType::Int64())));
  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      expected = (static_cast<uint64_t>(j) << 32) | i;
      CHECK_EQ(static_cast<int32_t>(expected), m.Call());
    }
  }
}

TEST(RunTruncateFloat64ToWord32P) {
  struct {
    double from;
    double raw;
  } kValues[] = {{0, 0},
                 {0.5, 0},
                 {-0.5, 0},
                 {1.5, 1},
                 {-1.5, -1},
                 {5.5, 5},
                 {-5.0, -5},
                 {std::numeric_limits<double>::quiet_NaN(), 0},
                 {std::numeric_limits<double>::infinity(), 0},
                 {-std::numeric_limits<double>::quiet_NaN(), 0},
                 {-std::numeric_limits<double>::infinity(), 0},
                 {4.94065645841e-324, 0},
                 {-4.94065645841e-324, 0},
                 {0.9999999999999999, 0},
                 {-0.9999999999999999, 0},
                 {4294967296.0, 0},
                 {-4294967296.0, 0},
                 {9223372036854775000.0, 4294966272.0},
                 {-9223372036854775000.0, -4294966272.0},
                 {4.5036e+15, 372629504},
                 {-4.5036e+15, -372629504},
                 {287524199.5377777, 0x11234567},
                 {-287524199.5377777, -0x11234567},
                 {2300193596.302222, 2300193596.0},
                 {-2300193596.302222, -2300193596.0},
                 {4600387192.604444, 305419896},
                 {-4600387192.604444, -305419896},
                 {4823855600872397.0, 1737075661},
                 {-4823855600872397.0, -1737075661},
                 {4503603922337791.0, -1},
                 {-4503603922337791.0, 1},
                 {4503601774854143.0, 2147483647},
                 {-4503601774854143.0, -2147483647},
                 {9007207844675582.0, -2},
                 {-9007207844675582.0, 2},
                 {2.4178527921507624e+24, -536870912},
                 {-2.4178527921507624e+24, 536870912},
                 {2.417853945072267e+24, -536870912},
                 {-2.417853945072267e+24, 536870912},
                 {4.8357055843015248e+24, -1073741824},
                 {-4.8357055843015248e+24, 1073741824},
                 {4.8357078901445341e+24, -1073741824},
                 {-4.8357078901445341e+24, 1073741824},
                 {2147483647.0, 2147483647.0},
                 {-2147483648.0, -2147483648.0},
                 {9.6714111686030497e+24, -2147483648.0},
                 {-9.6714111686030497e+24, -2147483648.0},
                 {9.6714157802890681e+24, -2147483648.0},
                 {-9.6714157802890681e+24, -2147483648.0},
                 {1.9342813113834065e+25, 2147483648.0},
                 {-1.9342813113834065e+25, 2147483648.0},
                 {3.868562622766813e+25, 0},
                 {-3.868562622766813e+25, 0},
                 {1.7976931348623157e+308, 0},
                 {-1.7976931348623157e+308, 0}};
  double input = -1.0;
  RawMachineAssemblerTester<int32_t> m;
  m.Return(m.TruncateFloat64ToWord32(
      m.LoadFromPointer(&input, MachineType::Float64())));
  for (size_t i = 0; i < arraysize(kValues); ++i) {
    input = kValues[i].from;
    uint64_t expected = static_cast<int64_t>(kValues[i].raw);
    CHECK_EQ(static_cast<int>(expected), m.Call());
  }
}

TEST(RunTruncateFloat64ToWord32SignExtension) {
  BufferedRawMachineAssemblerTester<int32_t> r;
  r.Return(r.Int32Sub(r.TruncateFloat64ToWord32(r.Float64Constant(-1.0)),
                      r.Int32Constant(0)));
  CHECK_EQ(-1, r.Call());
}

TEST(RunChangeFloat32ToFloat64) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float32());

  m.Return(m.ChangeFloat32ToFloat64(m.Parameter(0)));

  FOR_FLOAT32_INPUTS(i) { CHECK_DOUBLE_EQ(static_cast<double>(i), m.Call(i)); }
}


TEST(RunFloat32Constant) {
  FOR_FLOAT32_INPUTS(i) {
    BufferedRawMachineAssemblerTester<float> m;
    m.Return(m.Float32Constant(i));
    CHECK_FLOAT_EQ(i, m.Call());
  }
}


TEST(RunFloat64ExtractLowWord32) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float64());
  m.Return(m.Float64ExtractLowWord32(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) {
    uint32_t expected = static_cast<uint32_t>(base::bit_cast<uint64_t>(i));
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunFloat64ExtractHighWord32) {
  BufferedRawMachineAssemblerTester<uint32_t> m(MachineType::Float64());
  m.Return(m.Float64ExtractHighWord32(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) {
    uint32_t expected =
        static_cast<uint32_t>(base::bit_cast<uint64_t>(i) >> 32);
    CHECK_EQ(expected, m.Call(i));
  }
}


TEST(RunFloat64InsertLowWord32) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Int32());
  m.Return(m.Float64InsertLowWord32(m.Parameter(0), m.Parameter(1)));
  FOR_FLOAT64_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      double expected = base::bit_cast<double>(
          (base::bit_cast<uint64_t>(i) & ~(uint64_t{0xFFFFFFFF})) |
          (static_cast<uint64_t>(base::bit_cast<uint32_t>(j))));
      CHECK_DOUBLE_EQ(expected, m.Call(i, j));
    }
  }
}


TEST(RunFloat64InsertHighWord32) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64(),
                                              MachineType::Uint32());
  m.Return(m.Float64InsertHighWord32(m.Parameter(0), m.Parameter(1)));
  FOR_FLOAT64_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      uint64_t expected = (base::bit_cast<uint64_t>(i) & 0xFFFFFFFF) |
                          (static_cast<uint64_t>(j) << 32);

      CHECK_DOUBLE_EQ(base::bit_cast<double>(expected), m.Call(i, j));
    }
  }
}


TEST(RunFloat32Abs) {
  BufferedRawMachineAssemblerTester<float> m(MachineType::Float32());
  m.Return(m.Float32Abs(m.Parameter(0)));
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(std::abs(i), m.Call(i)); }
}


TEST(RunFloat64Abs) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Abs(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(std::abs(i), m.Call(i)); }
}

TEST(RunFloat64Acos) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Acos(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::acos(i), m.Call(i)); }
}

TEST(RunFloat64Acosh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Acosh(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::acosh(i), m.Call(i)); }
}

TEST(RunFloat64Asin) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Asin(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::asin(i), m.Call(i)); }
}

TEST(RunFloat64Asinh) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Asinh(m.Parameter(0)));
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(base::ieee754::asinh(i), m.Call(i)); }
}

TEST(RunFloat64Atan) {
  BufferedRawMachineAssemblerTester<double> m(MachineType::Float64());
  m.Return(m.Float64Atan(m.Parameter(0)));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::quiet_NaN())));
  CHECK(std::isnan(m.Call(std::numeric_limits<double>::signaling_NaN())));
  CHEC
```