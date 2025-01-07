Response:
Let's break down the thought process for analyzing this Go code snippet and answering the user's request.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the code looking for familiar Go idioms and keywords related to testing and data manipulation. I notice:

* **`package main` (Implied):**  While not explicitly stated, the context of `asn1_test.go` strongly suggests this is within a `_test` package. This immediately tells me the primary purpose is testing.
* **`import` statements:**  `bytes`, `encoding/hex`, `fmt`, `reflect`, `strings`, `testing`, `time`. These are standard Go libraries, giving clues about the functionality being tested (byte manipulation, hex encoding, formatting, deep comparison, string operations, testing framework, time handling).
* **`var` declarations:**  `berData`, `stringSliceTestData`, `explicitTaggedTimeTestData`, `bmpStringTests`. These likely hold test data.
* **`func Test...`:**  This confirms it's a testing file using Go's built-in testing framework. Each `Test...` function tests a specific aspect.
* **Struct definitions:** `explicitTaggedTimeTest`, `implicitTaggedTimeTest`, `truncatedExplicitTagTest`, `invalidUTF8Test`, `unexported`, `exported`, `foo`, `taggedRawValue`, `untaggedRawValue`. These represent data structures used in the tests, likely mirroring ASN.1 structures.
* **`asn1:"..."` struct tags:** This is a strong indicator that the code is testing the `encoding/asn1` package, specifically its ability to marshal and unmarshal data based on ASN.1 encoding rules. The tags specify encoding options like `explicit`, `implicit`, `tag`, and data types like `utf8`.
* **`Marshal` and `Unmarshal`:** These function names, without explicit package qualifiers, strongly suggest interaction with the `encoding/asn1` package.
* **Specific ASN.1 terms:**  "UTCTime", "GeneralizedTime", "BMPString", "ObjectIdentifier", "NULL".

**2. Deduction of Core Functionality:**

Based on the keywords and the context of `asn1_test.go`, the primary function of this code is to test the `encoding/asn1` package. Specifically, it appears to be testing:

* **Basic data types:** Strings, slices of strings.
* **Tagged values:** Explicit and implicit tagging of data.
* **Time types:** Handling of `time.Time` values, potentially with different ASN.1 time encodings (UTCTime, GeneralizedTime).
* **Error handling:** Testing scenarios with invalid input (truncated tags, invalid UTF-8).
* **Handling of nil values.**
* **Visibility rules:** Ensuring unexported struct fields are handled correctly (likely by being ignored during marshaling).
* **`NULL` type:** Testing marshaling and unmarshaling of the ASN.1 `NULL` type.
* **`RawValue`:**  Testing the ability to work with raw ASN.1 encoded data.
* **`BMPString`:** Testing the handling of the Basic Multilingual Plane string type.
* **`ObjectIdentifier`:** Testing the handling of OIDs, including checking for minimal encoding.

**3. Analyzing Individual Test Functions:**

Now, I'd go through each `Test...` function to understand its specific purpose:

* **`TestStringSlice`:** Checks marshaling and unmarshaling of string slices, including handling escape characters and non-ASCII characters.
* **`TestExplicitTaggedTime`:** Verifies that `time.Time` can be unmarshaled from explicitly tagged UTCTime or GeneralizedTime values.
* **`TestImplicitTaggedTime`:** Checks that an implicitly tagged time with a tag value that coincides with GeneralizedTime is still correctly interpreted as UTCTime.
* **`TestTruncatedExplicitTag`:** Tests error handling when an explicitly tagged value is truncated.
* **`TestUnmarshalInvalidUTF8`:**  Ensures an error is returned when unmarshaling invalid UTF-8 data into a string field tagged as `utf8`.
* **`TestMarshalNilValue`:** Confirms that marshaling nil values results in an error.
* **`TestUnexportedStructField`:**  Checks that unexported struct fields cause errors during marshaling and unmarshaling.
* **`TestNull`:** Tests the marshaling and unmarshaling of the `NullRawValue`.
* **`TestExplicitTagRawValueStruct`:** Tests the combination of explicit tagging and `RawValue`.
* **`TestTaggedRawValue`:**  Explores how `RawValue` handles different ASN.1 tag classes (context-specific, application, private).
* **`TestBMPString`:** Tests the parsing of BMP strings from their hex-encoded representation.
* **`TestNonMinimalEncodedOID`:** Checks that the unmarshaler rejects non-minimally encoded Object Identifiers.

**4. Code Examples and Reasoning (Pre-computation/Analysis):**

For each test function, I would think about potential input and output scenarios based on the ASN.1 rules and the Go struct definitions. For instance, in `TestExplicitTaggedTime`, I see byte arrays representing ASN.1 encoded times and the expected `time.Time` values. I can mentally (or actually) perform the ASN.1 decoding to understand the mapping.

**5. Answering the User's Questions:**

With the understanding gained from the previous steps, I can now address the user's specific questions:

* **功能列表:**  This involves summarizing the purpose of each test function.
* **Go语言功能实现推理:**  The `asn1:"..."` tags are the key here. It points to the `encoding/asn1` package and its marshaling/unmarshaling capabilities.
* **代码举例:**  I can pick a simple test case, like `TestStringSlice`, and show how `Marshal` and `Unmarshal` are used, along with example input and output.
* **命令行参数处理:** Since it's a testing file, there are no specific command-line arguments being handled directly *within this code*. I'd explain that Go tests are usually run with `go test`.
* **易犯错的点:** I'd analyze the test cases that involve errors (invalid UTF-8, unexported fields, non-minimal OIDs) to identify potential pitfalls for users of the `encoding/asn1` package. For example, forgetting about explicit vs. implicit tagging, or not being careful with UTF-8 encoding.
* **功能归纳 (Part 2):**  This is a higher-level summary of the overall purpose of the code snippet (testing the `encoding/asn1` package).

**Self-Correction/Refinement During the Process:**

* Initially, I might only see "tags" and not immediately connect them to ASN.1. However, the presence of `encoding/asn1` in the file path quickly clarifies this.
* I might initially focus too much on the *specific* data being tested (e.g., the URLs in `berData`) and not enough on the *general* principles being validated (e.g., handling of different ASN.1 string types). I'd then shift my focus to the broader functionality being tested.
* I might miss subtle aspects like the implicit tagging behavior in `TestImplicitTaggedTime`. Careful analysis of the test data and the function's description helps to catch these details.

By following this structured approach, I can systematically analyze the code and provide a comprehensive and accurate answer to the user's request.
好的，让我们来归纳一下您提供的 Go 语言代码片段的功能。

**功能归纳**

这段代码是 Go 语言标准库 `encoding/asn1` 包的测试文件 `asn1_test.go` 的一部分。它的主要功能是**测试 `encoding/asn1` 包中 ASN.1 数据的编码和解码功能是否正确**。

具体来说，这段代码测试了以下几个方面：

* **基本数据类型的编码和解码:**  测试了字符串切片 (`[]string`) 的编码和解码。
* **显式标签的时间类型:**  测试了带有显式标签 (`explicit, tag:0`) 的 `time.Time` 类型的编码和解码，并验证了可以正确解析 UTCTime 和 GeneralizedTime 两种格式。
* **隐式标签的时间类型:** 测试了带有隐式标签 (`tag:24`) 的 `time.Time` 类型的解码，并验证了即使标签值与 `GENERALIZEDTIME` 的标签相同，也能正确解析为 `UTCTime`。
* **处理截断的显式标签:** 测试了当 ASN.1 数据中显式标签的值被截断时的解码行为，期望能产生错误。
* **处理无效的 UTF-8 编码:**  测试了解码 UTF-8 字符串时遇到无效 UTF-8 编码的处理，期望能返回包含 "UTF" 的错误信息。
* **处理 nil 值:** 测试了对 `nil` 值进行编码的行为，期望能产生错误。
* **处理未导出的结构体字段:** 测试了包含未导出的字段的结构体在编码和解码时的行为，期望能产生特定的结构性错误。
* **`NULL` 类型的处理:** 测试了 `asn1.NullRawValue` 的编码和解码，验证其与预定义的 `NullBytes` 的一致性。
* **显式标签的 `RawValue` 结构体:** 测试了包含带有显式标签的 `asn1.RawValue` 字段的结构体的编码和解码。
* **带标签的 `RawValue`:** 测试了 `asn1.RawValue` 字段在不同 ASN.1 标签类型下的解码行为，包括上下文相关的标签、应用标签和私有标签。
* **BMP 字符串的解码:** 测试了使用 `parseBMPString` 函数解码 BMP 字符串的功能。
* **非最小化编码的 OID:** 测试了解码非最小化编码的对象标识符（OID）时是否会报错。
* **对象标识符的字符串表示性能:** 使用基准测试来评估将 `ObjectIdentifier` 转换为字符串的性能。

**总结**

这段代码通过定义各种测试用例和结构体，模拟不同的 ASN.1 数据结构和编码场景，然后使用 `encoding/asn1` 包的 `Marshal` 和 `Unmarshal` 函数进行编码和解码操作，并验证结果是否符合预期。这有助于确保 `encoding/asn1` 包的正确性和健壮性。

Prompt: 
```
这是路径为go/src/encoding/asn1/asn1_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
0x64, 0x20, 0x62, 0x79, 0x20, 0x68,
	0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x69, 0x70,
	0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x30, 0x2f, 0x06, 0x09, 0x60,
	0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x02, 0x04, 0x22, 0x16, 0x20, 0x68,
	0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x69, 0x70,
	0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61,
	0x32, 0x30, 0x30, 0x32, 0x2f, 0x30, 0x43, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x86, 0xf8, 0x42, 0x01, 0x04, 0x04, 0x36, 0x16, 0x34, 0x68, 0x74, 0x74, 0x70,
	0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x69, 0x70, 0x73, 0x63, 0x61,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61, 0x32, 0x30, 0x30,
	0x32, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61, 0x32, 0x30, 0x30, 0x32, 0x43, 0x4c,
	0x41, 0x53, 0x45, 0x41, 0x31, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x46, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x03, 0x04, 0x39, 0x16, 0x37,
	0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x69,
	0x70, 0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x70, 0x73, 0x63,
	0x61, 0x32, 0x30, 0x30, 0x32, 0x2f, 0x72, 0x65, 0x76, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x4c, 0x41, 0x53, 0x45, 0x41, 0x31, 0x2e, 0x68, 0x74,
	0x6d, 0x6c, 0x3f, 0x30, 0x43, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8,
	0x42, 0x01, 0x07, 0x04, 0x36, 0x16, 0x34, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a,
	0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x69, 0x70, 0x73, 0x63, 0x61, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61, 0x32, 0x30, 0x30, 0x32, 0x2f,
	0x72, 0x65, 0x6e, 0x65, 0x77, 0x61, 0x6c, 0x43, 0x4c, 0x41, 0x53, 0x45, 0x41,
	0x31, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x3f, 0x30, 0x41, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x08, 0x04, 0x34, 0x16, 0x32, 0x68, 0x74,
	0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x69, 0x70, 0x73,
	0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61, 0x32,
	0x30, 0x30, 0x32, 0x2f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x43, 0x4c, 0x41,
	0x53, 0x45, 0x41, 0x31, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x30, 0x81, 0x83, 0x06,
	0x03, 0x55, 0x1d, 0x1f, 0x04, 0x7c, 0x30, 0x7a, 0x30, 0x39, 0xa0, 0x37, 0xa0,
	0x35, 0x86, 0x33, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77,
	0x2e, 0x69, 0x70, 0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x70,
	0x73, 0x63, 0x61, 0x32, 0x30, 0x30, 0x32, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61,
	0x32, 0x30, 0x30, 0x32, 0x43, 0x4c, 0x41, 0x53, 0x45, 0x41, 0x31, 0x2e, 0x63,
	0x72, 0x6c, 0x30, 0x3d, 0xa0, 0x3b, 0xa0, 0x39, 0x86, 0x37, 0x68, 0x74, 0x74,
	0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x62, 0x61, 0x63, 0x6b, 0x2e, 0x69,
	0x70, 0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x69, 0x70, 0x73, 0x63,
	0x61, 0x32, 0x30, 0x30, 0x32, 0x2f, 0x69, 0x70, 0x73, 0x63, 0x61, 0x32, 0x30,
	0x30, 0x32, 0x43, 0x4c, 0x41, 0x53, 0x45, 0x41, 0x31, 0x2e, 0x63, 0x72, 0x6c,
	0x30, 0x32, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04,
	0x26, 0x30, 0x24, 0x30, 0x22, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
	0x30, 0x01, 0x86, 0x16, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63,
	0x73, 0x70, 0x2e, 0x69, 0x70, 0x73, 0x63, 0x61, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
	0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x68, 0xee, 0x79, 0x97, 0x97, 0xdd, 0x3b,
	0xef, 0x16, 0x6a, 0x06, 0xf2, 0x14, 0x9a, 0x6e, 0xcd, 0x9e, 0x12, 0xf7, 0xaa,
	0x83, 0x10, 0xbd, 0xd1, 0x7c, 0x98, 0xfa, 0xc7, 0xae, 0xd4, 0x0e, 0x2c, 0x9e,
	0x38, 0x05, 0x9d, 0x52, 0x60, 0xa9, 0x99, 0x0a, 0x81, 0xb4, 0x98, 0x90, 0x1d,
	0xae, 0xbb, 0x4a, 0xd7, 0xb9, 0xdc, 0x88, 0x9e, 0x37, 0x78, 0x41, 0x5b, 0xf7,
	0x82, 0xa5, 0xf2, 0xba, 0x41, 0x25, 0x5a, 0x90, 0x1a, 0x1e, 0x45, 0x38, 0xa1,
	0x52, 0x58, 0x75, 0x94, 0x26, 0x44, 0xfb, 0x20, 0x07, 0xba, 0x44, 0xcc, 0xe5,
	0x4a, 0x2d, 0x72, 0x3f, 0x98, 0x47, 0xf6, 0x26, 0xdc, 0x05, 0x46, 0x05, 0x07,
	0x63, 0x21, 0xab, 0x46, 0x9b, 0x9c, 0x78, 0xd5, 0x54, 0x5b, 0x3d, 0x0c, 0x1e,
	0xc8, 0x64, 0x8c, 0xb5, 0x50, 0x23, 0x82, 0x6f, 0xdb, 0xb8, 0x22, 0x1c, 0x43,
	0x96, 0x07, 0xa8, 0xbb,
}

var stringSliceTestData = [][]string{
	{"foo", "bar"},
	{"foo", "\\bar"},
	{"foo", "\"bar\""},
	{"foo", "åäö"},
}

func TestStringSlice(t *testing.T) {
	for _, test := range stringSliceTestData {
		bs, err := Marshal(test)
		if err != nil {
			t.Error(err)
		}

		var res []string
		_, err = Unmarshal(bs, &res)
		if err != nil {
			t.Error(err)
		}

		if fmt.Sprintf("%v", res) != fmt.Sprintf("%v", test) {
			t.Errorf("incorrect marshal/unmarshal; %v != %v", res, test)
		}
	}
}

type explicitTaggedTimeTest struct {
	Time time.Time `asn1:"explicit,tag:0"`
}

var explicitTaggedTimeTestData = []struct {
	in  []byte
	out explicitTaggedTimeTest
}{
	{[]byte{0x30, 0x11, 0xa0, 0xf, 0x17, 0xd, '9', '1', '0', '5', '0', '6', '1', '6', '4', '5', '4', '0', 'Z'},
		explicitTaggedTimeTest{time.Date(1991, 05, 06, 16, 45, 40, 0, time.UTC)}},
	{[]byte{0x30, 0x17, 0xa0, 0xf, 0x18, 0x13, '2', '0', '1', '0', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', '+', '0', '6', '0', '7'},
		explicitTaggedTimeTest{time.Date(2010, 01, 02, 03, 04, 05, 0, time.FixedZone("", 6*60*60+7*60))}},
}

func TestExplicitTaggedTime(t *testing.T) {
	// Test that a time.Time will match either tagUTCTime or
	// tagGeneralizedTime.
	for i, test := range explicitTaggedTimeTestData {
		var got explicitTaggedTimeTest
		_, err := Unmarshal(test.in, &got)
		if err != nil {
			t.Errorf("Unmarshal failed at index %d %v", i, err)
		}
		if !got.Time.Equal(test.out.Time) {
			t.Errorf("#%d: got %v, want %v", i, got.Time, test.out.Time)
		}
	}
}

type implicitTaggedTimeTest struct {
	Time time.Time `asn1:"tag:24"`
}

func TestImplicitTaggedTime(t *testing.T) {
	// An implicitly tagged time value, that happens to have an implicit
	// tag equal to a GENERALIZEDTIME, should still be parsed as a UTCTime.
	// (There's no "timeType" in fieldParameters to determine what type of
	// time should be expected when implicitly tagged.)
	der := []byte{0x30, 0x0f, 0x80 | 24, 0xd, '9', '1', '0', '5', '0', '6', '1', '6', '4', '5', '4', '0', 'Z'}
	var result implicitTaggedTimeTest
	if _, err := Unmarshal(der, &result); err != nil {
		t.Fatalf("Error while parsing: %s", err)
	}
	if expected := time.Date(1991, 05, 06, 16, 45, 40, 0, time.UTC); !result.Time.Equal(expected) {
		t.Errorf("Wrong result. Got %v, want %v", result.Time, expected)
	}
}

type truncatedExplicitTagTest struct {
	Test int `asn1:"explicit,tag:0"`
}

func TestTruncatedExplicitTag(t *testing.T) {
	// This crashed Unmarshal in the past. See #11154.
	der := []byte{
		0x30, // SEQUENCE
		0x02, // two bytes long
		0xa0, // context-specific, tag 0
		0x30, // 48 bytes long
	}

	var result truncatedExplicitTagTest
	if _, err := Unmarshal(der, &result); err == nil {
		t.Error("Unmarshal returned without error")
	}
}

type invalidUTF8Test struct {
	Str string `asn1:"utf8"`
}

func TestUnmarshalInvalidUTF8(t *testing.T) {
	data := []byte("0\x05\f\x03a\xc9c")
	var result invalidUTF8Test
	_, err := Unmarshal(data, &result)

	const expectedSubstring = "UTF"
	if err == nil {
		t.Fatal("Successfully unmarshaled invalid UTF-8 data")
	} else if !strings.Contains(err.Error(), expectedSubstring) {
		t.Fatalf("Expected error to mention %q but error was %q", expectedSubstring, err.Error())
	}
}

func TestMarshalNilValue(t *testing.T) {
	nilValueTestData := []any{
		nil,
		struct{ V any }{},
	}
	for i, test := range nilValueTestData {
		if _, err := Marshal(test); err == nil {
			t.Fatalf("#%d: successfully marshaled nil value", i)
		}
	}
}

type unexported struct {
	X int
	y int
}

type exported struct {
	X int
	Y int
}

func TestUnexportedStructField(t *testing.T) {
	want := StructuralError{"struct contains unexported fields"}

	_, err := Marshal(unexported{X: 5, y: 1})
	if err != want {
		t.Errorf("got %v, want %v", err, want)
	}

	bs, err := Marshal(exported{X: 5, Y: 1})
	if err != nil {
		t.Fatal(err)
	}
	var u unexported
	_, err = Unmarshal(bs, &u)
	if err != want {
		t.Errorf("got %v, want %v", err, want)
	}
}

func TestNull(t *testing.T) {
	marshaled, err := Marshal(NullRawValue)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(NullBytes, marshaled) {
		t.Errorf("Expected Marshal of NullRawValue to yield %x, got %x", NullBytes, marshaled)
	}

	unmarshaled := RawValue{}
	if _, err := Unmarshal(NullBytes, &unmarshaled); err != nil {
		t.Fatal(err)
	}

	unmarshaled.FullBytes = NullRawValue.FullBytes
	if len(unmarshaled.Bytes) == 0 {
		// DeepEqual considers a nil slice and an empty slice to be different.
		unmarshaled.Bytes = NullRawValue.Bytes
	}

	if !reflect.DeepEqual(NullRawValue, unmarshaled) {
		t.Errorf("Expected Unmarshal of NullBytes to yield %v, got %v", NullRawValue, unmarshaled)
	}
}

func TestExplicitTagRawValueStruct(t *testing.T) {
	type foo struct {
		A RawValue `asn1:"optional,explicit,tag:5"`
		B []byte   `asn1:"optional,explicit,tag:6"`
	}
	before := foo{B: []byte{1, 2, 3}}
	derBytes, err := Marshal(before)
	if err != nil {
		t.Fatal(err)
	}

	var after foo
	if rest, err := Unmarshal(derBytes, &after); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}

	got := fmt.Sprintf("%#v", after)
	want := fmt.Sprintf("%#v", before)
	if got != want {
		t.Errorf("got %s, want %s (DER: %x)", got, want, derBytes)
	}
}

func TestTaggedRawValue(t *testing.T) {
	type taggedRawValue struct {
		A RawValue `asn1:"tag:5"`
	}
	type untaggedRawValue struct {
		A RawValue
	}
	const isCompound = 0x20
	const tag = 5

	tests := []struct {
		shouldMatch bool
		derBytes    []byte
	}{
		{false, []byte{0x30, 3, TagInteger, 1, 1}},
		{true, []byte{0x30, 3, (ClassContextSpecific << 6) | tag, 1, 1}},
		{true, []byte{0x30, 3, (ClassContextSpecific << 6) | tag | isCompound, 1, 1}},
		{false, []byte{0x30, 3, (ClassApplication << 6) | tag | isCompound, 1, 1}},
		{false, []byte{0x30, 3, (ClassPrivate << 6) | tag | isCompound, 1, 1}},
	}

	for i, test := range tests {
		var tagged taggedRawValue
		if _, err := Unmarshal(test.derBytes, &tagged); (err == nil) != test.shouldMatch {
			t.Errorf("#%d: unexpected result parsing %x: %s", i, test.derBytes, err)
		}

		// An untagged RawValue should accept anything.
		var untagged untaggedRawValue
		if _, err := Unmarshal(test.derBytes, &untagged); err != nil {
			t.Errorf("#%d: unexpected failure parsing %x with untagged RawValue: %s", i, test.derBytes, err)
		}
	}
}

var bmpStringTests = []struct {
	decoded    string
	encodedHex string
}{
	{"", "0000"},
	// Example from https://tools.ietf.org/html/rfc7292#appendix-B.
	{"Beavis", "0042006500610076006900730000"},
	// Some characters from the "Letterlike Symbols Unicode block".
	{"\u2115 - Double-struck N", "21150020002d00200044006f00750062006c0065002d00730074007200750063006b0020004e0000"},
}

func TestBMPString(t *testing.T) {
	for i, test := range bmpStringTests {
		encoded, err := hex.DecodeString(test.encodedHex)
		if err != nil {
			t.Fatalf("#%d: failed to decode from hex string", i)
		}

		decoded, err := parseBMPString(encoded)

		if err != nil {
			t.Errorf("#%d: decoding output gave an error: %s", i, err)
			continue
		}

		if decoded != test.decoded {
			t.Errorf("#%d: decoding output resulted in %q, but it should have been %q", i, decoded, test.decoded)
			continue
		}
	}
}

func TestNonMinimalEncodedOID(t *testing.T) {
	h, err := hex.DecodeString("060a2a80864886f70d01010b")
	if err != nil {
		t.Fatalf("failed to decode from hex string: %s", err)
	}
	var oid ObjectIdentifier
	_, err = Unmarshal(h, &oid)
	if err == nil {
		t.Fatalf("accepted non-minimally encoded oid")
	}
}

func BenchmarkObjectIdentifierString(b *testing.B) {
	oidPublicKeyRSA := ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	for i := 0; i < b.N; i++ {
		_ = oidPublicKeyRSA.String()
	}
}

"""




```