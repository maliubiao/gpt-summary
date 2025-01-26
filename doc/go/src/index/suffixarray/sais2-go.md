Response:
The user wants to understand the functionality of the provided Go code snippet. The code seems to be part of a suffix array construction algorithm, specifically the SA-IS (Suffix Array by Induced Sorting) algorithm.

Here's a breakdown of the thinking process to analyze the code:

1. **Identify the core function:** The file name `sais2.go` and the function names containing "sais" strongly suggest this code implements the SA-IS algorithm.

2. **Look for entry points:**  Functions like `text_64` seem to be higher-level entry points, as they perform basic checks and then call the core `sais_8_64` function. The `_64` suffix likely indicates it operates on 64-bit integers for suffix array indices. The `_8` in `sais_8_64` likely refers to the character size (bytes in this case).

3. **Analyze the `sais_*` functions:** These functions are the heart of the algorithm. They handle different data types (`[]byte`, `[]int32`, `[]int64`). The structure of these functions is remarkably similar, suggesting a generic algorithm adapted for different input types.

4. **Identify key sub-steps:** The comments within the `sais_*` functions mention phases like `placeLMS`, `induceSubL`, `induceSubS`, `length`, `assignID`, `map`, `recurse`, `unmap`, and `expand`, and `induceL`, `induceS`. These are likely the individual steps of the SA-IS algorithm. The comments also explicitly mention that each of these calls makes one scan through the `sa` array.

5. **Focus on `placeLMS_*`:**  The comments within `placeLMS_8_64` explain the concept of L-characters, S-characters, and LMS-substrings. This confirms that the code is indeed implementing a sophisticated suffix array construction technique. The backward scan and the logic for identifying LMS-substring starts are crucial.

6. **Understand the role of `freq` and `bucket`:** The comments mention that these slices hold character frequencies and bucket-sort offsets. This is a common technique in efficient sorting algorithms, particularly radix sort and its variants.

7. **Infer the overall algorithm:** Based on the function names and the identified substeps, the code likely implements the following SA-IS algorithm flow:
    * Identify LMS-substrings (`placeLMS`).
    * Recursively sort the LMS-suffixes.
    * Induce the positions of all other suffixes based on the sorted LMS-suffixes (`induceL`, `induceS`).

8. **Examine helper functions:** Functions like `freq_*`, `bucketMin_*`, and `bucketMax_*` are helper functions for calculating frequencies and setting up buckets for the induced sorting steps.

9. **Address the user's specific questions:**
    * **Functionality:** Summarize the purpose of the functions (suffix array construction using SA-IS).
    * **Go feature:** Identify the use of slices, generics (although not explicit Go generics, the similar structure of `sais_*` suggests a conceptual genericity), and possibly in-place array manipulation.
    * **Code example:**  Demonstrate how to use the `text_64` function.
    * **Assumptions and I/O:**  The input is a byte slice, and the output is a sorted suffix array.
    * **Command-line arguments:**  The provided code doesn't seem to directly handle command-line arguments.
    * **Common mistakes:** Focus on the `panic` conditions related to slice lengths.
    * **Part 1 Summary:** Summarize the functionality covered in the provided snippet.

10. **Refine the answer:** Organize the information logically, use clear and concise language, and provide concrete examples where requested. Ensure the explanation is accessible to someone with some understanding of suffix arrays but might not be deeply familiar with the SA-IS algorithm.
这段Go语言代码是 `suffixarray` 包的一部分，实现了 **SA-IS (Skew Algorithm for Induced Suffix Sorting)** 算法的一种变体，用于构建 **后缀数组 (Suffix Array)**。

**功能归纳:**

这段代码的主要功能是实现高效的后缀数组构建。它包含以下几个关键步骤：

1. **初始化和参数校验:**
   - `text_64` 是一个入口函数，接收 `[]byte` 类型的文本和用于存储后缀数组的 `[]int64` 切片。它会进行一些基本的参数校验，例如确保文本和后缀数组的长度一致。
   - `sais_8_64`, `sais_32`, `sais_64` 是核心的 SA-IS 算法实现，分别针对 `[]byte`, `[]int32`, `[]int64` 类型的文本。它们也进行参数校验，确保临时缓冲区 `tmp` 的大小足够。

2. **处理基本情况:**
   - 对于空文本或只有一个字符的文本，它们会直接返回或设置后缀数组。

3. **计算字符频率和桶偏移:**
   - `freq_8_64`, `freq_32`, `freq_64` 用于计算文本中每个字符的出现频率。
   - `bucketMin_8_64`, `bucketMin_32`, `bucketMin_64` 和 `bucketMax_8_64`, `bucketMax_32`, `bucketMax_64` 用于计算桶排序的起始和结束偏移量。

4. **放置 LMS (Left-Most S-type) 子串:**
   - `placeLMS_8_64`, `placeLMS_32`, `placeLMS_64` 识别并按照它们在原文本中的位置，将 LMS 子串的起始或结束位置放入后缀数组 `sa` 中。LMS 子串是后缀数组构建的关键中间步骤。

5. **诱导排序 (Induce Sorting):**
   - `induceSubL_8_64`, `induceSubL_32`, `induceSubL_64`：根据已经排序的部分后缀（主要是 LMS 后缀），诱导排序出以 L 型字符开始的后缀。
   - `induceSubS_8_64`, `induceSubS_32`, `induceSubS_64`：根据已经排序的部分后缀，诱导排序出以 S 型字符开始的后缀。
   - `induceL_8_64`, `induceL_32`, `induceL_64` 和 `induceS_8_64`, `induceS_32`, `induceS_64`：是对 `induceSubL` 和 `induceSubS` 更一般化的诱导排序步骤。

6. **处理 LMS 子串的排序和递归:**
   - `length_8_64`, `length_32`, `length_64` 计算 LMS 子串的长度或编码表示。
   - `assignID_8_64`, `assignID_32`, `assignID_64` 为每个不同的 LMS 子串分配一个唯一的 ID。
   - `map_64`, `map_32` 将后缀数组中 LMS 子串的位置映射到它们对应的 ID。
   - `recurse_64`, `recurse_32` 对 LMS 子串的 ID 序列进行递归的后缀数组构建，这是 SA-IS 算法的核心思想。
   - `unmap_8_64`, `unmap_32` 将递归结果映射回原始文本的索引。
   - `expand_8_64`, `expand_32`, `expand_64` 根据 LMS 子串的排序结果，扩展到完整的后缀数组排序。

**推断 Go 语言功能的实现 (示例):**

这段代码大量使用了 **切片 (slice)** 和 **数组 (array)** 来存储和操作数据。同时，它也展示了 **函数式编程** 的思想，将复杂的算法分解为多个小的、职责单一的函数。

**示例 (假设输入与输出):**

```go
package main

import (
	"fmt"
	"index/suffixarray"
)

func main() {
	text := []byte("banana")
	sa := make([]int64, len(text))
	suffixarray.Text(text, sa) // 调用 Text 函数，实际会调用到 text_64

	fmt.Println("Text:", string(text))
	fmt.Println("Suffix Array:", sa) // 输出: [5 3 1 0 4 2]
}
```

**假设的输入与输出解释:**

- **输入:** 字节切片 `text`: `[]byte{'b', 'a', 'n', 'a', 'n', 'a'}`，表示字符串 "banana"。
- **输出:** 整数切片 `sa`: `[]int64{5, 3, 1, 0, 4, 2}`。这个切片存储了排序后的后缀在原字符串中的起始索引。
    - `5`: "a" (最后一个)
    - `3`: "ana"
    - `1`: "anana"
    - `0`: "banana"
    - `4`: "na"
    - `2`: "nana"

**命令行参数:**

这段代码本身并没有直接处理命令行参数。它是一个库函数，通常被其他程序调用。如果需要处理命令行参数，调用此库的程序会使用 `flag` 或其他命令行参数解析库。

**使用者易犯错的点:**

1. **`panic("suffixarray: misuse of text_64")`:**  调用 `text_64` 函数时，必须确保传入的 `text` 和 `sa` 切片的长度一致。这是最容易犯的错误，因为需要手动创建 `sa` 切片。
   ```go
   text := []byte("test")
   // 错误示例：sa 的长度不正确
   sa := make([]int64, len(text)+1)
   suffixarray.Text(text, sa) // 这里会 panic
   ```
   正确的做法是：
   ```go
   text := []byte("test")
   sa := make([]int64, len(text))
   suffixarray.Text(text, sa)
   ```

2. **`panic("suffixarray: misuse of sais_8_64")`:** 调用 `sais_8_64` 等核心函数时，需要确保临时缓冲区 `tmp` 的大小至少为 `textMax`。对于 `sais_8_64`，`textMax` 通常是 256 (ASCII 字符集大小)。如果使用不当，也会导致 panic。不过，用户通常不会直接调用 `sais_*` 函数，而是通过 `Text` 等高层函数。

**第1部分功能归纳:**

这段代码实现了 SA-IS 算法的核心部分，用于构建后缀数组。它包含了：

- 针对不同数据类型 (byte, int32, int64) 的 SA-IS 算法实现 (`sais_8_64`, `sais_32`, `sais_64`)。
- 计算字符频率和桶偏移的辅助函数 (`freq_*`, `bucketMin_*`, `bucketMax_*`)。
- 识别和放置 LMS 子串的函数 (`placeLMS_*`)。
- 部分诱导排序的函数 (`induceSubL_*`, `induceSubS_*`)。
- 处理 LMS 子串长度、ID 分配、映射和递归的函数 (`length_*`, `assignID_*`, `map_*`, `recurse_*`, `unmap_*`).

总而言之，这段代码是构建后缀数组的关键组成部分，使用了高效的 SA-IS 算法。它通过分步骤的处理，实现了对输入文本后缀的排序，并将排序结果存储在后缀数组中。

Prompt: 
```
这是路径为go/src/index/suffixarray/sais2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by go generate; DO NOT EDIT.

package suffixarray

func text_64(text []byte, sa []int64) {
	if int(int64(len(text))) != len(text) || len(text) != len(sa) {
		panic("suffixarray: misuse of text_64")
	}
	sais_8_64(text, 256, sa, make([]int64, 2*256))
}

func sais_8_64(text []byte, textMax int, sa, tmp []int64) {
	if len(sa) != len(text) || len(tmp) < textMax {
		panic("suffixarray: misuse of sais_8_64")
	}

	// Trivial base cases. Sorting 0 or 1 things is easy.
	if len(text) == 0 {
		return
	}
	if len(text) == 1 {
		sa[0] = 0
		return
	}

	// Establish slices indexed by text character
	// holding character frequency and bucket-sort offsets.
	// If there's only enough tmp for one slice,
	// we make it the bucket offsets and recompute
	// the character frequency each time we need it.
	var freq, bucket []int64
	if len(tmp) >= 2*textMax {
		freq, bucket = tmp[:textMax], tmp[textMax:2*textMax]
		freq[0] = -1 // mark as uninitialized
	} else {
		freq, bucket = nil, tmp[:textMax]
	}

	// The SAIS algorithm.
	// Each of these calls makes one scan through sa.
	// See the individual functions for documentation
	// about each's role in the algorithm.
	numLMS := placeLMS_8_64(text, sa, freq, bucket)
	if numLMS <= 1 {
		// 0 or 1 items are already sorted. Do nothing.
	} else {
		induceSubL_8_64(text, sa, freq, bucket)
		induceSubS_8_64(text, sa, freq, bucket)
		length_8_64(text, sa, numLMS)
		maxID := assignID_8_64(text, sa, numLMS)
		if maxID < numLMS {
			map_64(sa, numLMS)
			recurse_64(sa, tmp, numLMS, maxID)
			unmap_8_64(text, sa, numLMS)
		} else {
			// If maxID == numLMS, then each LMS-substring
			// is unique, so the relative ordering of two LMS-suffixes
			// is determined by just the leading LMS-substring.
			// That is, the LMS-suffix sort order matches the
			// (simpler) LMS-substring sort order.
			// Copy the original LMS-substring order into the
			// suffix array destination.
			copy(sa, sa[len(sa)-numLMS:])
		}
		expand_8_64(text, freq, bucket, sa, numLMS)
	}
	induceL_8_64(text, sa, freq, bucket)
	induceS_8_64(text, sa, freq, bucket)

	// Mark for caller that we overwrote tmp.
	tmp[0] = -1
}

func sais_32(text []int32, textMax int, sa, tmp []int32) {
	if len(sa) != len(text) || len(tmp) < textMax {
		panic("suffixarray: misuse of sais_32")
	}

	// Trivial base cases. Sorting 0 or 1 things is easy.
	if len(text) == 0 {
		return
	}
	if len(text) == 1 {
		sa[0] = 0
		return
	}

	// Establish slices indexed by text character
	// holding character frequency and bucket-sort offsets.
	// If there's only enough tmp for one slice,
	// we make it the bucket offsets and recompute
	// the character frequency each time we need it.
	var freq, bucket []int32
	if len(tmp) >= 2*textMax {
		freq, bucket = tmp[:textMax], tmp[textMax:2*textMax]
		freq[0] = -1 // mark as uninitialized
	} else {
		freq, bucket = nil, tmp[:textMax]
	}

	// The SAIS algorithm.
	// Each of these calls makes one scan through sa.
	// See the individual functions for documentation
	// about each's role in the algorithm.
	numLMS := placeLMS_32(text, sa, freq, bucket)
	if numLMS <= 1 {
		// 0 or 1 items are already sorted. Do nothing.
	} else {
		induceSubL_32(text, sa, freq, bucket)
		induceSubS_32(text, sa, freq, bucket)
		length_32(text, sa, numLMS)
		maxID := assignID_32(text, sa, numLMS)
		if maxID < numLMS {
			map_32(sa, numLMS)
			recurse_32(sa, tmp, numLMS, maxID)
			unmap_32(text, sa, numLMS)
		} else {
			// If maxID == numLMS, then each LMS-substring
			// is unique, so the relative ordering of two LMS-suffixes
			// is determined by just the leading LMS-substring.
			// That is, the LMS-suffix sort order matches the
			// (simpler) LMS-substring sort order.
			// Copy the original LMS-substring order into the
			// suffix array destination.
			copy(sa, sa[len(sa)-numLMS:])
		}
		expand_32(text, freq, bucket, sa, numLMS)
	}
	induceL_32(text, sa, freq, bucket)
	induceS_32(text, sa, freq, bucket)

	// Mark for caller that we overwrote tmp.
	tmp[0] = -1
}

func sais_64(text []int64, textMax int, sa, tmp []int64) {
	if len(sa) != len(text) || len(tmp) < textMax {
		panic("suffixarray: misuse of sais_64")
	}

	// Trivial base cases. Sorting 0 or 1 things is easy.
	if len(text) == 0 {
		return
	}
	if len(text) == 1 {
		sa[0] = 0
		return
	}

	// Establish slices indexed by text character
	// holding character frequency and bucket-sort offsets.
	// If there's only enough tmp for one slice,
	// we make it the bucket offsets and recompute
	// the character frequency each time we need it.
	var freq, bucket []int64
	if len(tmp) >= 2*textMax {
		freq, bucket = tmp[:textMax], tmp[textMax:2*textMax]
		freq[0] = -1 // mark as uninitialized
	} else {
		freq, bucket = nil, tmp[:textMax]
	}

	// The SAIS algorithm.
	// Each of these calls makes one scan through sa.
	// See the individual functions for documentation
	// about each's role in the algorithm.
	numLMS := placeLMS_64(text, sa, freq, bucket)
	if numLMS <= 1 {
		// 0 or 1 items are already sorted. Do nothing.
	} else {
		induceSubL_64(text, sa, freq, bucket)
		induceSubS_64(text, sa, freq, bucket)
		length_64(text, sa, numLMS)
		maxID := assignID_64(text, sa, numLMS)
		if maxID < numLMS {
			map_64(sa, numLMS)
			recurse_64(sa, tmp, numLMS, maxID)
			unmap_64(text, sa, numLMS)
		} else {
			// If maxID == numLMS, then each LMS-substring
			// is unique, so the relative ordering of two LMS-suffixes
			// is determined by just the leading LMS-substring.
			// That is, the LMS-suffix sort order matches the
			// (simpler) LMS-substring sort order.
			// Copy the original LMS-substring order into the
			// suffix array destination.
			copy(sa, sa[len(sa)-numLMS:])
		}
		expand_64(text, freq, bucket, sa, numLMS)
	}
	induceL_64(text, sa, freq, bucket)
	induceS_64(text, sa, freq, bucket)

	// Mark for caller that we overwrote tmp.
	tmp[0] = -1
}

func freq_8_64(text []byte, freq, bucket []int64) []int64 {
	if freq != nil && freq[0] >= 0 {
		return freq // already computed
	}
	if freq == nil {
		freq = bucket
	}

	freq = freq[:256] // eliminate bounds check for freq[c] below
	clear(freq)
	for _, c := range text {
		freq[c]++
	}
	return freq
}

func freq_32(text []int32, freq, bucket []int32) []int32 {
	if freq != nil && freq[0] >= 0 {
		return freq // already computed
	}
	if freq == nil {
		freq = bucket
	}

	clear(freq)
	for _, c := range text {
		freq[c]++
	}
	return freq
}

func freq_64(text []int64, freq, bucket []int64) []int64 {
	if freq != nil && freq[0] >= 0 {
		return freq // already computed
	}
	if freq == nil {
		freq = bucket
	}

	clear(freq)
	for _, c := range text {
		freq[c]++
	}
	return freq
}

func bucketMin_8_64(text []byte, freq, bucket []int64) {
	freq = freq_8_64(text, freq, bucket)
	freq = freq[:256]     // establish len(freq) = 256, so 0 ≤ i < 256 below
	bucket = bucket[:256] // eliminate bounds check for bucket[i] below
	total := int64(0)
	for i, n := range freq {
		bucket[i] = total
		total += n
	}
}

func bucketMin_32(text []int32, freq, bucket []int32) {
	freq = freq_32(text, freq, bucket)
	total := int32(0)
	for i, n := range freq {
		bucket[i] = total
		total += n
	}
}

func bucketMin_64(text []int64, freq, bucket []int64) {
	freq = freq_64(text, freq, bucket)
	total := int64(0)
	for i, n := range freq {
		bucket[i] = total
		total += n
	}
}

func bucketMax_8_64(text []byte, freq, bucket []int64) {
	freq = freq_8_64(text, freq, bucket)
	freq = freq[:256]     // establish len(freq) = 256, so 0 ≤ i < 256 below
	bucket = bucket[:256] // eliminate bounds check for bucket[i] below
	total := int64(0)
	for i, n := range freq {
		total += n
		bucket[i] = total
	}
}

func bucketMax_32(text []int32, freq, bucket []int32) {
	freq = freq_32(text, freq, bucket)
	total := int32(0)
	for i, n := range freq {
		total += n
		bucket[i] = total
	}
}

func bucketMax_64(text []int64, freq, bucket []int64) {
	freq = freq_64(text, freq, bucket)
	total := int64(0)
	for i, n := range freq {
		total += n
		bucket[i] = total
	}
}

func placeLMS_8_64(text []byte, sa, freq, bucket []int64) int {
	bucketMax_8_64(text, freq, bucket)

	numLMS := 0
	lastB := int64(-1)
	bucket = bucket[:256] // eliminate bounds check for bucket[c1] below

	// The next stanza of code (until the blank line) loop backward
	// over text, stopping to execute a code body at each position i
	// such that text[i] is an L-character and text[i+1] is an S-character.
	// That is, i+1 is the position of the start of an LMS-substring.
	// These could be hoisted out into a function with a callback,
	// but at a significant speed cost. Instead, we just write these
	// seven lines a few times in this source file. The copies below
	// refer back to the pattern established by this original as the
	// "LMS-substring iterator".
	//
	// In every scan through the text, c0, c1 are successive characters of text.
	// In this backward scan, c0 == text[i] and c1 == text[i+1].
	// By scanning backward, we can keep track of whether the current
	// position is type-S or type-L according to the usual definition:
	//
	//	- position len(text) is type S with text[len(text)] == -1 (the sentinel)
	//	- position i is type S if text[i] < text[i+1], or if text[i] == text[i+1] && i+1 is type S.
	//	- position i is type L if text[i] > text[i+1], or if text[i] == text[i+1] && i+1 is type L.
	//
	// The backward scan lets us maintain the current type,
	// update it when we see c0 != c1, and otherwise leave it alone.
	// We want to identify all S positions with a preceding L.
	// Position len(text) is one such position by definition, but we have
	// nowhere to write it down, so we eliminate it by untruthfully
	// setting isTypeS = false at the start of the loop.
	c0, c1, isTypeS := byte(0), byte(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Bucket the index i+1 for the start of an LMS-substring.
			b := bucket[c1] - 1
			bucket[c1] = b
			sa[b] = int64(i + 1)
			lastB = b
			numLMS++
		}
	}

	// We recorded the LMS-substring starts but really want the ends.
	// Luckily, with two differences, the start indexes and the end indexes are the same.
	// The first difference is that the rightmost LMS-substring's end index is len(text),
	// so the caller must pretend that sa[-1] == len(text), as noted above.
	// The second difference is that the first leftmost LMS-substring start index
	// does not end an earlier LMS-substring, so as an optimization we can omit
	// that leftmost LMS-substring start index (the last one we wrote).
	//
	// Exception: if numLMS <= 1, the caller is not going to bother with
	// the recursion at all and will treat the result as containing LMS-substring starts.
	// In that case, we don't remove the final entry.
	if numLMS > 1 {
		sa[lastB] = 0
	}
	return numLMS
}

func placeLMS_32(text []int32, sa, freq, bucket []int32) int {
	bucketMax_32(text, freq, bucket)

	numLMS := 0
	lastB := int32(-1)

	// The next stanza of code (until the blank line) loop backward
	// over text, stopping to execute a code body at each position i
	// such that text[i] is an L-character and text[i+1] is an S-character.
	// That is, i+1 is the position of the start of an LMS-substring.
	// These could be hoisted out into a function with a callback,
	// but at a significant speed cost. Instead, we just write these
	// seven lines a few times in this source file. The copies below
	// refer back to the pattern established by this original as the
	// "LMS-substring iterator".
	//
	// In every scan through the text, c0, c1 are successive characters of text.
	// In this backward scan, c0 == text[i] and c1 == text[i+1].
	// By scanning backward, we can keep track of whether the current
	// position is type-S or type-L according to the usual definition:
	//
	//	- position len(text) is type S with text[len(text)] == -1 (the sentinel)
	//	- position i is type S if text[i] < text[i+1], or if text[i] == text[i+1] && i+1 is type S.
	//	- position i is type L if text[i] > text[i+1], or if text[i] == text[i+1] && i+1 is type L.
	//
	// The backward scan lets us maintain the current type,
	// update it when we see c0 != c1, and otherwise leave it alone.
	// We want to identify all S positions with a preceding L.
	// Position len(text) is one such position by definition, but we have
	// nowhere to write it down, so we eliminate it by untruthfully
	// setting isTypeS = false at the start of the loop.
	c0, c1, isTypeS := int32(0), int32(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Bucket the index i+1 for the start of an LMS-substring.
			b := bucket[c1] - 1
			bucket[c1] = b
			sa[b] = int32(i + 1)
			lastB = b
			numLMS++
		}
	}

	// We recorded the LMS-substring starts but really want the ends.
	// Luckily, with two differences, the start indexes and the end indexes are the same.
	// The first difference is that the rightmost LMS-substring's end index is len(text),
	// so the caller must pretend that sa[-1] == len(text), as noted above.
	// The second difference is that the first leftmost LMS-substring start index
	// does not end an earlier LMS-substring, so as an optimization we can omit
	// that leftmost LMS-substring start index (the last one we wrote).
	//
	// Exception: if numLMS <= 1, the caller is not going to bother with
	// the recursion at all and will treat the result as containing LMS-substring starts.
	// In that case, we don't remove the final entry.
	if numLMS > 1 {
		sa[lastB] = 0
	}
	return numLMS
}

func placeLMS_64(text []int64, sa, freq, bucket []int64) int {
	bucketMax_64(text, freq, bucket)

	numLMS := 0
	lastB := int64(-1)

	// The next stanza of code (until the blank line) loop backward
	// over text, stopping to execute a code body at each position i
	// such that text[i] is an L-character and text[i+1] is an S-character.
	// That is, i+1 is the position of the start of an LMS-substring.
	// These could be hoisted out into a function with a callback,
	// but at a significant speed cost. Instead, we just write these
	// seven lines a few times in this source file. The copies below
	// refer back to the pattern established by this original as the
	// "LMS-substring iterator".
	//
	// In every scan through the text, c0, c1 are successive characters of text.
	// In this backward scan, c0 == text[i] and c1 == text[i+1].
	// By scanning backward, we can keep track of whether the current
	// position is type-S or type-L according to the usual definition:
	//
	//	- position len(text) is type S with text[len(text)] == -1 (the sentinel)
	//	- position i is type S if text[i] < text[i+1], or if text[i] == text[i+1] && i+1 is type S.
	//	- position i is type L if text[i] > text[i+1], or if text[i] == text[i+1] && i+1 is type L.
	//
	// The backward scan lets us maintain the current type,
	// update it when we see c0 != c1, and otherwise leave it alone.
	// We want to identify all S positions with a preceding L.
	// Position len(text) is one such position by definition, but we have
	// nowhere to write it down, so we eliminate it by untruthfully
	// setting isTypeS = false at the start of the loop.
	c0, c1, isTypeS := int64(0), int64(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Bucket the index i+1 for the start of an LMS-substring.
			b := bucket[c1] - 1
			bucket[c1] = b
			sa[b] = int64(i + 1)
			lastB = b
			numLMS++
		}
	}

	// We recorded the LMS-substring starts but really want the ends.
	// Luckily, with two differences, the start indexes and the end indexes are the same.
	// The first difference is that the rightmost LMS-substring's end index is len(text),
	// so the caller must pretend that sa[-1] == len(text), as noted above.
	// The second difference is that the first leftmost LMS-substring start index
	// does not end an earlier LMS-substring, so as an optimization we can omit
	// that leftmost LMS-substring start index (the last one we wrote).
	//
	// Exception: if numLMS <= 1, the caller is not going to bother with
	// the recursion at all and will treat the result as containing LMS-substring starts.
	// In that case, we don't remove the final entry.
	if numLMS > 1 {
		sa[lastB] = 0
	}
	return numLMS
}

func induceSubL_8_64(text []byte, sa, freq, bucket []int64) {
	// Initialize positions for left side of character buckets.
	bucketMin_8_64(text, freq, bucket)
	bucket = bucket[:256] // eliminate bounds check for bucket[cB] below

	// As we scan the array left-to-right, each sa[i] = j > 0 is a correctly
	// sorted suffix array entry (for text[j:]) for which we know that j-1 is type L.
	// Because j-1 is type L, inserting it into sa now will sort it correctly.
	// But we want to distinguish a j-1 with j-2 of type L from type S.
	// We can process the former but want to leave the latter for the caller.
	// We record the difference by negating j-1 if it is preceded by type S.
	// Either way, the insertion (into the text[j-1] bucket) is guaranteed to
	// happen at sa[i´] for some i´ > i, that is, in the portion of sa we have
	// yet to scan. A single pass therefore sees indexes j, j-1, j-2, j-3,
	// and so on, in sorted but not necessarily adjacent order, until it finds
	// one preceded by an index of type S, at which point it must stop.
	//
	// As we scan through the array, we clear the worked entries (sa[i] > 0) to zero,
	// and we flip sa[i] < 0 to -sa[i], so that the loop finishes with sa containing
	// only the indexes of the leftmost L-type indexes for each LMS-substring.
	//
	// The suffix array sa therefore serves simultaneously as input, output,
	// and a miraculously well-tailored work queue.

	// placeLMS_8_64 left out the implicit entry sa[-1] == len(text),
	// corresponding to the identified type-L index len(text)-1.
	// Process it before the left-to-right scan of sa proper.
	// See body in loop for commentary.
	k := len(text) - 1
	c0, c1 := text[k-1], text[k]
	if c0 < c1 {
		k = -k
	}

	// Cache recently used bucket index:
	// we're processing suffixes in sorted order
	// and accessing buckets indexed by the
	// byte before the sorted order, which still
	// has very good locality.
	// Invariant: b is cached, possibly dirty copy of bucket[cB].
	cB := c1
	b := bucket[cB]
	sa[b] = int64(k)
	b++

	for i := 0; i < len(sa); i++ {
		j := int(sa[i])
		if j == 0 {
			// Skip empty entry.
			continue
		}
		if j < 0 {
			// Leave discovered type-S index for caller.
			sa[i] = int64(-j)
			continue
		}
		sa[i] = 0

		// Index j was on work queue, meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is L-type, queue k for processing later in this loop.
		// If k-1 is S-type (text[k-1] < text[k]), queue -k to save for the caller.
		k := j - 1
		c0, c1 := text[k-1], text[k]
		if c0 < c1 {
			k = -k
		}

		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[cB]
		}
		sa[b] = int64(k)
		b++
	}
}

func induceSubL_32(text []int32, sa, freq, bucket []int32) {
	// Initialize positions for left side of character buckets.
	bucketMin_32(text, freq, bucket)

	// As we scan the array left-to-right, each sa[i] = j > 0 is a correctly
	// sorted suffix array entry (for text[j:]) for which we know that j-1 is type L.
	// Because j-1 is type L, inserting it into sa now will sort it correctly.
	// But we want to distinguish a j-1 with j-2 of type L from type S.
	// We can process the former but want to leave the latter for the caller.
	// We record the difference by negating j-1 if it is preceded by type S.
	// Either way, the insertion (into the text[j-1] bucket) is guaranteed to
	// happen at sa[i´] for some i´ > i, that is, in the portion of sa we have
	// yet to scan. A single pass therefore sees indexes j, j-1, j-2, j-3,
	// and so on, in sorted but not necessarily adjacent order, until it finds
	// one preceded by an index of type S, at which point it must stop.
	//
	// As we scan through the array, we clear the worked entries (sa[i] > 0) to zero,
	// and we flip sa[i] < 0 to -sa[i], so that the loop finishes with sa containing
	// only the indexes of the leftmost L-type indexes for each LMS-substring.
	//
	// The suffix array sa therefore serves simultaneously as input, output,
	// and a miraculously well-tailored work queue.

	// placeLMS_32 left out the implicit entry sa[-1] == len(text),
	// corresponding to the identified type-L index len(text)-1.
	// Process it before the left-to-right scan of sa proper.
	// See body in loop for commentary.
	k := len(text) - 1
	c0, c1 := text[k-1], text[k]
	if c0 < c1 {
		k = -k
	}

	// Cache recently used bucket index:
	// we're processing suffixes in sorted order
	// and accessing buckets indexed by the
	// int32 before the sorted order, which still
	// has very good locality.
	// Invariant: b is cached, possibly dirty copy of bucket[cB].
	cB := c1
	b := bucket[cB]
	sa[b] = int32(k)
	b++

	for i := 0; i < len(sa); i++ {
		j := int(sa[i])
		if j == 0 {
			// Skip empty entry.
			continue
		}
		if j < 0 {
			// Leave discovered type-S index for caller.
			sa[i] = int32(-j)
			continue
		}
		sa[i] = 0

		// Index j was on work queue, meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is L-type, queue k for processing later in this loop.
		// If k-1 is S-type (text[k-1] < text[k]), queue -k to save for the caller.
		k := j - 1
		c0, c1 := text[k-1], text[k]
		if c0 < c1 {
			k = -k
		}

		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[cB]
		}
		sa[b] = int32(k)
		b++
	}
}

func induceSubL_64(text []int64, sa, freq, bucket []int64) {
	// Initialize positions for left side of character buckets.
	bucketMin_64(text, freq, bucket)

	// As we scan the array left-to-right, each sa[i] = j > 0 is a correctly
	// sorted suffix array entry (for text[j:]) for which we know that j-1 is type L.
	// Because j-1 is type L, inserting it into sa now will sort it correctly.
	// But we want to distinguish a j-1 with j-2 of type L from type S.
	// We can process the former but want to leave the latter for the caller.
	// We record the difference by negating j-1 if it is preceded by type S.
	// Either way, the insertion (into the text[j-1] bucket) is guaranteed to
	// happen at sa[i´] for some i´ > i, that is, in the portion of sa we have
	// yet to scan. A single pass therefore sees indexes j, j-1, j-2, j-3,
	// and so on, in sorted but not necessarily adjacent order, until it finds
	// one preceded by an index of type S, at which point it must stop.
	//
	// As we scan through the array, we clear the worked entries (sa[i] > 0) to zero,
	// and we flip sa[i] < 0 to -sa[i], so that the loop finishes with sa containing
	// only the indexes of the leftmost L-type indexes for each LMS-substring.
	//
	// The suffix array sa therefore serves simultaneously as input, output,
	// and a miraculously well-tailored work queue.

	// placeLMS_64 left out the implicit entry sa[-1] == len(text),
	// corresponding to the identified type-L index len(text)-1.
	// Process it before the left-to-right scan of sa proper.
	// See body in loop for commentary.
	k := len(text) - 1
	c0, c1 := text[k-1], text[k]
	if c0 < c1 {
		k = -k
	}

	// Cache recently used bucket index:
	// we're processing suffixes in sorted order
	// and accessing buckets indexed by the
	// int64 before the sorted order, which still
	// has very good locality.
	// Invariant: b is cached, possibly dirty copy of bucket[cB].
	cB := c1
	b := bucket[cB]
	sa[b] = int64(k)
	b++

	for i := 0; i < len(sa); i++ {
		j := int(sa[i])
		if j == 0 {
			// Skip empty entry.
			continue
		}
		if j < 0 {
			// Leave discovered type-S index for caller.
			sa[i] = int64(-j)
			continue
		}
		sa[i] = 0

		// Index j was on work queue, meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is L-type, queue k for processing later in this loop.
		// If k-1 is S-type (text[k-1] < text[k]), queue -k to save for the caller.
		k := j - 1
		c0, c1 := text[k-1], text[k]
		if c0 < c1 {
			k = -k
		}

		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[cB]
		}
		sa[b] = int64(k)
		b++
	}
}

func induceSubS_8_64(text []byte, sa, freq, bucket []int64) {
	// Initialize positions for right side of character buckets.
	bucketMax_8_64(text, freq, bucket)
	bucket = bucket[:256] // eliminate bounds check for bucket[cB] below

	// Analogous to induceSubL_8_64 above,
	// as we scan the array right-to-left, each sa[i] = j > 0 is a correctly
	// sorted suffix array entry (for text[j:]) for which we know that j-1 is type S.
	// Because j-1 is type S, inserting it into sa now will sort it correctly.
	// But we want to distinguish a j-1 with j-2 of type S from type L.
	// We can process the former but want to leave the latter for the caller.
	// We record the difference by negating j-1 if it is preceded by type L.
	// Either way, the insertion (into the text[j-1] bucket) is guaranteed to
	// happen at sa[i´] for some i´ < i, that is, in the portion of sa we have
	// yet to scan. A single pass therefore sees indexes j, j-1, j-2, j-3,
	// and so on, in sorted but not necessarily adjacent order, until it finds
	// one preceded by an index of type L, at which point it must stop.
	// That index (preceded by one of type L) is an LMS-substring start.
	//
	// As we scan through the array, we clear the worked entries (sa[i] > 0) to zero,
	// and we flip sa[i] < 0 to -sa[i] and compact into the top of sa,
	// so that the loop finishes with the top of sa containing exactly
	// the LMS-substring start indexes, sorted by LMS-substring.

	// Cache recently used bucket index:
	cB := byte(0)
	b := bucket[cB]

	top := len(sa)
	for i := len(sa) - 1; i >= 0; i-- {
		j := int(sa[i])
		if j == 0 {
			// Skip empty entry.
			continue
		}
		sa[i] = 0
		if j < 0 {
			// Leave discovered LMS-substring start index for caller.
			top--
			sa[top] = int64(-j)
			continue
		}

		// Index j was on work queue, meaning k := j-1 is S-type,
		// so we can now place k correctly into sa.
		// If k-1 is S-type, queue k for processing later in this loop.
		// If k-1 is L-type (text[k-1] > text[k]), queue -k to save for the caller.
		k := j - 1
		c1 := text[k]
		c0 := text[k-1]
		if c0 > c1 {
			k = -k
		}

		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[cB]
		}
		b--
		sa[b] = int64(k)
	}
}

func induceSubS_32(text []int32, sa, freq, bucket []int32) {
	// Initialize positions for right side of character buckets.
	bucketMax_32(text, freq, bucket)

	// Analogous to induceSubL_32 above,
	// as we scan the array right-to-left, each sa[i] = j > 0 is a correctly
	// sorted suffix array entry (for text[j:]) for which we know that j-1 is type S.
	// Because j-1 is type S, inserting it into sa now will sort it correctly.
	// But we want to distinguish a j-1 with j-2 of type S from type L.
	// We can process the former but want to leave the latter for the caller.
	// We record the difference by negating j-1 if it is preceded by type L.
	// Either way, the insertion (into the text[j-1] bucket) is guaranteed to
	// happen at sa[i´] for some i´ < i, that is, in the portion of sa we have
	// yet to scan. A single pass therefore sees indexes j, j-1, j-2, j-3,
	// and so on, in sorted but not necessarily adjacent order, until it finds
	// one preceded by an index of type L, at which point it must stop.
	// That index (preceded by one of type L) is an LMS-substring start.
	//
	// As we scan through the array, we clear the worked entries (sa[i] > 0) to zero,
	// and we flip sa[i] < 0 to -sa[i] and compact into the top of sa,
	// so that the loop finishes with the top of sa containing exactly
	// the LMS-substring start indexes, sorted by LMS-substring.

	// Cache recently used bucket index:
	cB := int32(0)
	b := bucket[cB]

	top := len(sa)
	for i := len(sa) - 1; i >= 0; i-- {
		j := int(sa[i])
		if j == 0 {
			// Skip empty entry.
			continue
		}
		sa[i] = 0
		if j < 0 {
			// Leave discovered LMS-substring start index for caller.
			top--
			sa[top] = int32(-j)
			continue
		}

		// Index j was on work queue, meaning k := j-1 is S-type,
		// so we can now place k correctly into sa.
		// If k-1 is S-type, queue k for processing later in this loop.
		// If k-1 is L-type (text[k-1] > text[k]), queue -k to save for the caller.
		k := j - 1
		c1 := text[k]
		c0 := text[k-1]
		if c0 > c1 {
			k = -k
		}

		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[cB]
		}
		b--
		sa[b] = int32(k)
	}
}

func induceSubS_64(text []int64, sa, freq, bucket []int64) {
	// Initialize positions for right side of character buckets.
	bucketMax_64(text, freq, bucket)

	// Analogous to induceSubL_64 above,
	// as we scan the array right-to-left, each sa[i] = j > 0 is a correctly
	// sorted suffix array entry (for text[j:]) for which we know that j-1 is type S.
	// Because j-1 is type S, inserting it into sa now will sort it correctly.
	// But we want to distinguish a j-1 with j-2 of type S from type L.
	// We can process the former but want to leave the latter for the caller.
	// We record the difference by negating j-1 if it is preceded by type L.
	// Either way, the insertion (into the text[j-1] bucket) is guaranteed to
	// happen at sa[i´] for some i´ < i, that is, in the portion of sa we have
	// yet to scan. A single pass therefore sees indexes j, j-1, j-2, j-3,
	// and so on, in sorted but not necessarily adjacent order, until it finds
	// one preceded by an index of type L, at which point it must stop.
	// That index (preceded by one of type L) is an LMS-substring start.
	//
	// As we scan through the array, we clear the worked entries (sa[i] > 0) to zero,
	// and we flip sa[i] < 0 to -sa[i] and compact into the top of sa,
	// so that the loop finishes with the top of sa containing exactly
	// the LMS-substring start indexes, sorted by LMS-substring.

	// Cache recently used bucket index:
	cB := int64(0)
	b := bucket[cB]

	top := len(sa)
	for i := len(sa) - 1; i >= 0; i-- {
		j := int(sa[i])
		if j == 0 {
			// Skip empty entry.
			continue
		}
		sa[i] = 0
		if j < 0 {
			// Leave discovered LMS-substring start index for caller.
			top--
			sa[top] = int64(-j)
			continue
		}

		// Index j was on work queue, meaning k := j-1 is S-type,
		// so we can now place k correctly into sa.
		// If k-1 is S-type, queue k for processing later in this loop.
		// If k-1 is L-type (text[k-1] > text[k]), queue -k to save for the caller.
		k := j - 1
		c1 := text[k]
		c0 := text[k-1]
		if c0 > c1 {
			k = -k
		}

		if cB != c1 {
			bucket[cB] = b
			cB = c1
			b = bucket[cB]
		}
		b--
		sa[b] = int64(k)
	}
}

func length_8_64(text []byte, sa []int64, numLMS int) {
	end := 0 // index of current LMS-substring end (0 indicates final LMS-substring)

	// The encoding of N text bytes into a “length” word
	// adds 1 to each byte, packs them into the bottom
	// N*8 bits of a word, and then bitwise inverts the result.
	// That is, the text sequence A B C (hex 41 42 43)
	// encodes as ^uint64(0x42_43_44).
	// LMS-substrings can never start or end with 0xFF.
	// Adding 1 ensures the encoded byte sequence never
	// starts or ends with 0x00, so that present bytes can be
	// distinguished from zero-padding in the top bits,
	// so the length need not be separately encoded.
	// Inverting the bytes increases the chance that a
	// 4-byte encoding will still be ≥ len(text).
	// In particular, if the first byte is ASCII (<= 0x7E, so +1 <= 0x7F)
	// then the high bit of the inversion will be set,
	// making it clearly not a valid length (it would be a negative one).
	//
	// cx holds the pre-inverted encoding (the packed incremented bytes).
	cx := uint64(0) // byte-only

	// This stanza (until the blank line) is the "LMS-substring iterator",
	// described in placeLMS_8_64 above, with one line added to maintain cx.
	c0, c1, isTypeS := byte(0), byte(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		cx = cx<<8 | uint64(c1+1) // byte-only
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Index j = i+1 is the start of an LMS-substring.
			// Compute length or encoded text to store in sa[j/2].
			j := i + 1
			var code int64
			if end == 0 {
				code = 0
			} else {
				code = int64(end - j)
				if code <= 64/8 && ^cx >= uint64(len(text)) { // byte-only
					code = int64(^cx) // byte-only
				} // byte-only
			}
			sa[j>>1] = code
			end = j + 1
			cx = uint64(c1 + 1) // byte-only
		}
	
"""




```