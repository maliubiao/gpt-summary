Response:
这是关于 Go 语言实现后缀数组构建算法 SA-IS 的代码片段。这个第二部分的代码主要包含以下几个方面的功能：

1. **计算 LMS 子串的长度或编码**: `length_32` 和 `length_64` 函数用于迭代识别 LMS 子串，并计算它们的长度或将其编码后存储在提供的 `sa` 数组中。编码方式是为了在有限的空间内存储足够的信息，同时也能区分不同的子串。

2. **为 LMS 子串分配 ID**: `assignID_8_64`, `assignID_32`, `assignID_64` 函数遍历已排序的 LMS 子串起始位置，并为每个不同的 LMS 子串分配一个唯一的 ID。这个过程会比较当前的 LMS 子串和上一个 LMS 子串，如果相同则使用相同的 ID，否则分配一个新的 ID。

3. **映射 LMS 子串的 ID**: `map_64` 函数将 LMS 子串的 ID 映射到更小的连续整数范围内。这通常是为递归调用做准备，缩小字符集的范围。

4. **递归构建后缀数组**: `recurse_64` 函数负责递归地构建子问题的后缀数组。它将 LMS 子串的 ID 序列作为新的文本，然后调用 `sais_64` 函数来构建这个新文本的后缀数组。该函数还处理了临时空间的分配和复用，以优化性能。

5. **逆映射 LMS 子串的起始位置**: `unmap_8_64`, `unmap_32`, `unmap_64` 函数将递归调用中得到的 LMS 子串的排序结果（ID 序列的后缀数组）逆映射回原始文本中的起始位置。

6. **根据 LMS 子串的顺序扩展后缀数组**: `expand_8_64`, `expand_32`, `expand_64` 函数使用已排序的 LMS 子串的起始位置来初始化最终的后缀数组。它从后向前遍历后缀数组，并根据 LMS 子串的位置填充相应的索引。

7. **诱导排序 L 型后缀**: `induceL_8_64`, `induceL_32`, `induceL_64` 函数利用已知的 LMS 型后缀的位置，通过诱导排序的方法来确定所有 L 型后缀在后缀数组中的位置。它从左向右扫描后缀数组，并根据当前后缀的类型和字符大小关系，将其前一个字符对应的后缀放入正确的位置。

8. **诱导排序 S 型后缀**: `induceS_8_64`, `induceS_32`, `induceS_64` 函数利用已知的 L 型后缀的位置，通过诱导排序的方法来确定所有 S 型后缀在后缀数组中的位置。它从右向左扫描后缀数组，并根据当前后缀的类型和字符大小关系，将其前一个字符对应的后缀放入正确的位置。

**归纳一下它的功能：**

这部分代码是 SA-IS 算法的核心实现，专注于处理 LMS 子串，并通过递归的方式构建后缀数组。它包含了识别、排序（通过递归调用）、映射和逆映射 LMS 子串的关键步骤，以及利用这些信息通过诱导排序来完成最终后缀数组的构建。这些函数针对不同大小的字符类型（byte, int32, int64）提供了相应的实现。
这是 Go 语言实现的 SA-IS (Suffix Array Induced Sorting) 算法的一部分，主要负责构建后缀数组的中间和最后阶段。

**功能归纳：**

这部分代码的主要功能是基于已识别出的 LMS (Leftmost S-type) 子串来构建完整的后缀数组。具体来说，它包含以下几个关键步骤：

1. **计算和存储 LMS 子串的信息：** `length_32` 和 `length_64` 函数用于识别文本中的 LMS 子串，并将其长度（或编码后的信息）存储在提供的 `sa` 数组的特定位置。这种编码方式是为了节省空间并在后续步骤中能够恢复子串信息。

2. **为 LMS 子串分配唯一 ID：** `assignID_8_64`, `assignID_32`, `assignID_64` 函数遍历已排序的 LMS 子串，并为每个不同的 LMS 子串分配一个唯一的整数 ID。这是为递归构建后缀数组做准备，将 LMS 子串视为新的字符进行排序。

3. **映射 LMS 子串 ID 到更小的范围：** `map_64` 函数将 LMS 子串的 ID 映射到一个更小的连续整数范围内。这有助于减小递归构建后缀数组时字符集的大小，提高效率。

4. **递归构建子问题的后缀数组：** `recurse_64` 函数负责处理 SA-IS 算法的递归部分。它将 LMS 子串的 ID 序列作为新的文本，然后递归调用 SA-IS 算法来构建这个新文本的后缀数组。这利用了 LMS 子串的特性，将原问题转化为一个更小的子问题。

5. **逆映射子问题后缀数组到原文本位置：** `unmap_8_64`, `unmap_32`, `unmap_64` 函数将递归调用得到的子问题后缀数组中的 ID 逆映射回原始文本中对应 LMS 子串的起始位置。

6. **根据 LMS 子串的顺序初始化后缀数组：** `expand_8_64`, `expand_32`, `expand_64` 函数使用已经排序的 LMS 子串的起始位置来初始化最终的后缀数组 `sa`。它从后向前填充 `sa` 数组中对应 LMS 子串的位置。

7. **诱导排序 L 型和 S 型后缀：**
   - `induceL_8_64`, `induceL_32`, `induceL_64` 函数执行诱导排序的 L 型 (Left-type) 部分。它利用已知的 LMS 型后缀的位置，从左向右扫描 `sa` 数组，根据字符的大小关系将 L 型后缀放置到正确的位置。
   - `induceS_8_64`, `induceS_32`, `induceS_64` 函数执行诱导排序的 S 型 (Right-type) 部分。它从右向左扫描 `sa` 数组，根据字符的大小关系将 S 型后缀放置到正确的位置。

**总而言之，这部分代码实现了 SA-IS 算法中至关重要的步骤，即利用 LMS 子串的信息，通过递归和诱导排序高效地构建出文本的后缀数组。**

由于这是代码片段，没有包含完整的 `sais2.go` 文件，因此无法提供完整的可运行示例或命令行参数处理信息。不过，根据代码的结构，可以推断出其主要功能是算法内部的实现细节，不太可能直接涉及命令行参数。

**使用者易犯错的点：**

虽然这段代码是算法的内部实现，普通使用者不会直接调用这些函数，但理解这些内部机制有助于避免在使用后缀数组时的一些常见错误，例如：

* **错误地理解后缀数组的含义：** 后缀数组 `sa` 存储的是原始文本的**后缀的起始索引**，按照字典序排序。
* **不理解 LMS 子串在算法中的作用：** LMS 子串是 SA-IS 算法的关键，理解其定义和特性有助于理解算法的效率来源。
* **假设后缀数组可以直接用于字符串匹配：** 虽然后缀数组可以用于字符串匹配，但通常需要配合 LCP (Longest Common Prefix) 数组等辅助数据结构才能实现高效的匹配。

希望以上解释能够帮助你理解这段 Go 代码的功能。

Prompt: 
```
这是路径为go/src/index/suffixarray/sais2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
}
}

func length_32(text []int32, sa []int32, numLMS int) {
	end := 0 // index of current LMS-substring end (0 indicates final LMS-substring)

	// The encoding of N text int32s into a “length” word
	// adds 1 to each int32, packs them into the bottom
	// N*8 bits of a word, and then bitwise inverts the result.
	// That is, the text sequence A B C (hex 41 42 43)
	// encodes as ^uint32(0x42_43_44).
	// LMS-substrings can never start or end with 0xFF.
	// Adding 1 ensures the encoded int32 sequence never
	// starts or ends with 0x00, so that present int32s can be
	// distinguished from zero-padding in the top bits,
	// so the length need not be separately encoded.
	// Inverting the int32s increases the chance that a
	// 4-int32 encoding will still be ≥ len(text).
	// In particular, if the first int32 is ASCII (<= 0x7E, so +1 <= 0x7F)
	// then the high bit of the inversion will be set,
	// making it clearly not a valid length (it would be a negative one).
	//
	// cx holds the pre-inverted encoding (the packed incremented int32s).

	// This stanza (until the blank line) is the "LMS-substring iterator",
	// described in placeLMS_32 above, with one line added to maintain cx.
	c0, c1, isTypeS := int32(0), int32(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Index j = i+1 is the start of an LMS-substring.
			// Compute length or encoded text to store in sa[j/2].
			j := i + 1
			var code int32
			if end == 0 {
				code = 0
			} else {
				code = int32(end - j)
			}
			sa[j>>1] = code
			end = j + 1
		}
	}
}

func length_64(text []int64, sa []int64, numLMS int) {
	end := 0 // index of current LMS-substring end (0 indicates final LMS-substring)

	// The encoding of N text int64s into a “length” word
	// adds 1 to each int64, packs them into the bottom
	// N*8 bits of a word, and then bitwise inverts the result.
	// That is, the text sequence A B C (hex 41 42 43)
	// encodes as ^uint64(0x42_43_44).
	// LMS-substrings can never start or end with 0xFF.
	// Adding 1 ensures the encoded int64 sequence never
	// starts or ends with 0x00, so that present int64s can be
	// distinguished from zero-padding in the top bits,
	// so the length need not be separately encoded.
	// Inverting the int64s increases the chance that a
	// 4-int64 encoding will still be ≥ len(text).
	// In particular, if the first int64 is ASCII (<= 0x7E, so +1 <= 0x7F)
	// then the high bit of the inversion will be set,
	// making it clearly not a valid length (it would be a negative one).
	//
	// cx holds the pre-inverted encoding (the packed incremented int64s).

	// This stanza (until the blank line) is the "LMS-substring iterator",
	// described in placeLMS_64 above, with one line added to maintain cx.
	c0, c1, isTypeS := int64(0), int64(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
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
			}
			sa[j>>1] = code
			end = j + 1
		}
	}
}

func assignID_8_64(text []byte, sa []int64, numLMS int) int {
	id := 0
	lastLen := int64(-1) // impossible
	lastPos := int64(0)
	for _, j := range sa[len(sa)-numLMS:] {
		// Is the LMS-substring at index j new, or is it the same as the last one we saw?
		n := sa[j/2]
		if n != lastLen {
			goto New
		}
		if uint64(n) >= uint64(len(text)) {
			// “Length” is really encoded full text, and they match.
			goto Same
		}
		{
			// Compare actual texts.
			n := int(n)
			this := text[j:][:n]
			last := text[lastPos:][:n]
			for i := 0; i < n; i++ {
				if this[i] != last[i] {
					goto New
				}
			}
			goto Same
		}
	New:
		id++
		lastPos = j
		lastLen = n
	Same:
		sa[j/2] = int64(id)
	}
	return id
}

func assignID_32(text []int32, sa []int32, numLMS int) int {
	id := 0
	lastLen := int32(-1) // impossible
	lastPos := int32(0)
	for _, j := range sa[len(sa)-numLMS:] {
		// Is the LMS-substring at index j new, or is it the same as the last one we saw?
		n := sa[j/2]
		if n != lastLen {
			goto New
		}
		if uint32(n) >= uint32(len(text)) {
			// “Length” is really encoded full text, and they match.
			goto Same
		}
		{
			// Compare actual texts.
			n := int(n)
			this := text[j:][:n]
			last := text[lastPos:][:n]
			for i := 0; i < n; i++ {
				if this[i] != last[i] {
					goto New
				}
			}
			goto Same
		}
	New:
		id++
		lastPos = j
		lastLen = n
	Same:
		sa[j/2] = int32(id)
	}
	return id
}

func assignID_64(text []int64, sa []int64, numLMS int) int {
	id := 0
	lastLen := int64(-1) // impossible
	lastPos := int64(0)
	for _, j := range sa[len(sa)-numLMS:] {
		// Is the LMS-substring at index j new, or is it the same as the last one we saw?
		n := sa[j/2]
		if n != lastLen {
			goto New
		}
		if uint64(n) >= uint64(len(text)) {
			// “Length” is really encoded full text, and they match.
			goto Same
		}
		{
			// Compare actual texts.
			n := int(n)
			this := text[j:][:n]
			last := text[lastPos:][:n]
			for i := 0; i < n; i++ {
				if this[i] != last[i] {
					goto New
				}
			}
			goto Same
		}
	New:
		id++
		lastPos = j
		lastLen = n
	Same:
		sa[j/2] = int64(id)
	}
	return id
}

func map_64(sa []int64, numLMS int) {
	w := len(sa)
	for i := len(sa) / 2; i >= 0; i-- {
		j := sa[i]
		if j > 0 {
			w--
			sa[w] = j - 1
		}
	}
}

func recurse_64(sa, oldTmp []int64, numLMS, maxID int) {
	dst, saTmp, text := sa[:numLMS], sa[numLMS:len(sa)-numLMS], sa[len(sa)-numLMS:]

	// Set up temporary space for recursive call.
	// We must pass sais_64 a tmp buffer with at least maxID entries.
	//
	// The subproblem is guaranteed to have length at most len(sa)/2,
	// so that sa can hold both the subproblem and its suffix array.
	// Nearly all the time, however, the subproblem has length < len(sa)/3,
	// in which case there is a subproblem-sized middle of sa that
	// we can reuse for temporary space (saTmp).
	// When recurse_64 is called from sais_8_64, oldTmp is length 512
	// (from text_64), and saTmp will typically be much larger, so we'll use saTmp.
	// When deeper recursions come back to recurse_64, now oldTmp is
	// the saTmp from the top-most recursion, it is typically larger than
	// the current saTmp (because the current sa gets smaller and smaller
	// as the recursion gets deeper), and we keep reusing that top-most
	// large saTmp instead of the offered smaller ones.
	//
	// Why is the subproblem length so often just under len(sa)/3?
	// See Nong, Zhang, and Chen, section 3.6 for a plausible explanation.
	// In brief, the len(sa)/2 case would correspond to an SLSLSLSLSLSL pattern
	// in the input, perfect alternation of larger and smaller input bytes.
	// Real text doesn't do that. If each L-type index is randomly followed
	// by either an L-type or S-type index, then half the substrings will
	// be of the form SLS, but the other half will be longer. Of that half,
	// half (a quarter overall) will be SLLS; an eighth will be SLLLS, and so on.
	// Not counting the final S in each (which overlaps the first S in the next),
	// This works out to an average length 2×½ + 3×¼ + 4×⅛ + ... = 3.
	// The space we need is further reduced by the fact that many of the
	// short patterns like SLS will often be the same character sequences
	// repeated throughout the text, reducing maxID relative to numLMS.
	//
	// For short inputs, the averages may not run in our favor, but then we
	// can often fall back to using the length-512 tmp available in the
	// top-most call. (Also a short allocation would not be a big deal.)
	//
	// For pathological inputs, we fall back to allocating a new tmp of length
	// max(maxID, numLMS/2). This level of the recursion needs maxID,
	// and all deeper levels of the recursion will need no more than numLMS/2,
	// so this one allocation is guaranteed to suffice for the entire stack
	// of recursive calls.
	tmp := oldTmp
	if len(tmp) < len(saTmp) {
		tmp = saTmp
	}
	if len(tmp) < numLMS {
		// TestSAIS/forcealloc reaches this code.
		n := maxID
		if n < numLMS/2 {
			n = numLMS / 2
		}
		tmp = make([]int64, n)
	}

	// sais_64 requires that the caller arrange to clear dst,
	// because in general the caller may know dst is
	// freshly-allocated and already cleared. But this one is not.
	clear(dst)
	sais_64(text, maxID, dst, tmp)
}

func unmap_8_64(text []byte, sa []int64, numLMS int) {
	unmap := sa[len(sa)-numLMS:]
	j := len(unmap)

	// "LMS-substring iterator" (see placeLMS_8_64 above).
	c0, c1, isTypeS := byte(0), byte(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Populate inverse map.
			j--
			unmap[j] = int64(i + 1)
		}
	}

	// Apply inverse map to subproblem suffix array.
	sa = sa[:numLMS]
	for i := 0; i < len(sa); i++ {
		sa[i] = unmap[sa[i]]
	}
}

func unmap_32(text []int32, sa []int32, numLMS int) {
	unmap := sa[len(sa)-numLMS:]
	j := len(unmap)

	// "LMS-substring iterator" (see placeLMS_32 above).
	c0, c1, isTypeS := int32(0), int32(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Populate inverse map.
			j--
			unmap[j] = int32(i + 1)
		}
	}

	// Apply inverse map to subproblem suffix array.
	sa = sa[:numLMS]
	for i := 0; i < len(sa); i++ {
		sa[i] = unmap[sa[i]]
	}
}

func unmap_64(text []int64, sa []int64, numLMS int) {
	unmap := sa[len(sa)-numLMS:]
	j := len(unmap)

	// "LMS-substring iterator" (see placeLMS_64 above).
	c0, c1, isTypeS := int64(0), int64(0), false
	for i := len(text) - 1; i >= 0; i-- {
		c0, c1 = text[i], c0
		if c0 < c1 {
			isTypeS = true
		} else if c0 > c1 && isTypeS {
			isTypeS = false

			// Populate inverse map.
			j--
			unmap[j] = int64(i + 1)
		}
	}

	// Apply inverse map to subproblem suffix array.
	sa = sa[:numLMS]
	for i := 0; i < len(sa); i++ {
		sa[i] = unmap[sa[i]]
	}
}

func expand_8_64(text []byte, freq, bucket, sa []int64, numLMS int) {
	bucketMax_8_64(text, freq, bucket)
	bucket = bucket[:256] // eliminate bound check for bucket[c] below

	// Loop backward through sa, always tracking
	// the next index to populate from sa[:numLMS].
	// When we get to one, populate it.
	// Zero the rest of the slots; they have dead values in them.
	x := numLMS - 1
	saX := sa[x]
	c := text[saX]
	b := bucket[c] - 1
	bucket[c] = b

	for i := len(sa) - 1; i >= 0; i-- {
		if i != int(b) {
			sa[i] = 0
			continue
		}
		sa[i] = saX

		// Load next entry to put down (if any).
		if x > 0 {
			x--
			saX = sa[x] // TODO bounds check
			c = text[saX]
			b = bucket[c] - 1
			bucket[c] = b
		}
	}
}

func expand_32(text []int32, freq, bucket, sa []int32, numLMS int) {
	bucketMax_32(text, freq, bucket)

	// Loop backward through sa, always tracking
	// the next index to populate from sa[:numLMS].
	// When we get to one, populate it.
	// Zero the rest of the slots; they have dead values in them.
	x := numLMS - 1
	saX := sa[x]
	c := text[saX]
	b := bucket[c] - 1
	bucket[c] = b

	for i := len(sa) - 1; i >= 0; i-- {
		if i != int(b) {
			sa[i] = 0
			continue
		}
		sa[i] = saX

		// Load next entry to put down (if any).
		if x > 0 {
			x--
			saX = sa[x] // TODO bounds check
			c = text[saX]
			b = bucket[c] - 1
			bucket[c] = b
		}
	}
}

func expand_64(text []int64, freq, bucket, sa []int64, numLMS int) {
	bucketMax_64(text, freq, bucket)

	// Loop backward through sa, always tracking
	// the next index to populate from sa[:numLMS].
	// When we get to one, populate it.
	// Zero the rest of the slots; they have dead values in them.
	x := numLMS - 1
	saX := sa[x]
	c := text[saX]
	b := bucket[c] - 1
	bucket[c] = b

	for i := len(sa) - 1; i >= 0; i-- {
		if i != int(b) {
			sa[i] = 0
			continue
		}
		sa[i] = saX

		// Load next entry to put down (if any).
		if x > 0 {
			x--
			saX = sa[x] // TODO bounds check
			c = text[saX]
			b = bucket[c] - 1
			bucket[c] = b
		}
	}
}

func induceL_8_64(text []byte, sa, freq, bucket []int64) {
	// Initialize positions for left side of character buckets.
	bucketMin_8_64(text, freq, bucket)
	bucket = bucket[:256] // eliminate bounds check for bucket[cB] below

	// This scan is similar to the one in induceSubL_8_64 above.
	// That one arranges to clear all but the leftmost L-type indexes.
	// This scan leaves all the L-type indexes and the original S-type
	// indexes, but it negates the positive leftmost L-type indexes
	// (the ones that induceS_8_64 needs to process).

	// expand_8_64 left out the implicit entry sa[-1] == len(text),
	// corresponding to the identified type-L index len(text)-1.
	// Process it before the left-to-right scan of sa proper.
	// See body in loop for commentary.
	k := len(text) - 1
	c0, c1 := text[k-1], text[k]
	if c0 < c1 {
		k = -k
	}

	// Cache recently used bucket index.
	cB := c1
	b := bucket[cB]
	sa[b] = int64(k)
	b++

	for i := 0; i < len(sa); i++ {
		j := int(sa[i])
		if j <= 0 {
			// Skip empty or negated entry (including negated zero).
			continue
		}

		// Index j was on work queue, meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is L-type, queue k for processing later in this loop.
		// If k-1 is S-type (text[k-1] < text[k]), queue -k to save for the caller.
		// If k is zero, k-1 doesn't exist, so we only need to leave it
		// for the caller. The caller can't tell the difference between
		// an empty slot and a non-empty zero, but there's no need
		// to distinguish them anyway: the final suffix array will end up
		// with one zero somewhere, and that will be a real zero.
		k := j - 1
		c1 := text[k]
		if k > 0 {
			if c0 := text[k-1]; c0 < c1 {
				k = -k
			}
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

func induceL_32(text []int32, sa, freq, bucket []int32) {
	// Initialize positions for left side of character buckets.
	bucketMin_32(text, freq, bucket)

	// This scan is similar to the one in induceSubL_32 above.
	// That one arranges to clear all but the leftmost L-type indexes.
	// This scan leaves all the L-type indexes and the original S-type
	// indexes, but it negates the positive leftmost L-type indexes
	// (the ones that induceS_32 needs to process).

	// expand_32 left out the implicit entry sa[-1] == len(text),
	// corresponding to the identified type-L index len(text)-1.
	// Process it before the left-to-right scan of sa proper.
	// See body in loop for commentary.
	k := len(text) - 1
	c0, c1 := text[k-1], text[k]
	if c0 < c1 {
		k = -k
	}

	// Cache recently used bucket index.
	cB := c1
	b := bucket[cB]
	sa[b] = int32(k)
	b++

	for i := 0; i < len(sa); i++ {
		j := int(sa[i])
		if j <= 0 {
			// Skip empty or negated entry (including negated zero).
			continue
		}

		// Index j was on work queue, meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is L-type, queue k for processing later in this loop.
		// If k-1 is S-type (text[k-1] < text[k]), queue -k to save for the caller.
		// If k is zero, k-1 doesn't exist, so we only need to leave it
		// for the caller. The caller can't tell the difference between
		// an empty slot and a non-empty zero, but there's no need
		// to distinguish them anyway: the final suffix array will end up
		// with one zero somewhere, and that will be a real zero.
		k := j - 1
		c1 := text[k]
		if k > 0 {
			if c0 := text[k-1]; c0 < c1 {
				k = -k
			}
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

func induceL_64(text []int64, sa, freq, bucket []int64) {
	// Initialize positions for left side of character buckets.
	bucketMin_64(text, freq, bucket)

	// This scan is similar to the one in induceSubL_64 above.
	// That one arranges to clear all but the leftmost L-type indexes.
	// This scan leaves all the L-type indexes and the original S-type
	// indexes, but it negates the positive leftmost L-type indexes
	// (the ones that induceS_64 needs to process).

	// expand_64 left out the implicit entry sa[-1] == len(text),
	// corresponding to the identified type-L index len(text)-1.
	// Process it before the left-to-right scan of sa proper.
	// See body in loop for commentary.
	k := len(text) - 1
	c0, c1 := text[k-1], text[k]
	if c0 < c1 {
		k = -k
	}

	// Cache recently used bucket index.
	cB := c1
	b := bucket[cB]
	sa[b] = int64(k)
	b++

	for i := 0; i < len(sa); i++ {
		j := int(sa[i])
		if j <= 0 {
			// Skip empty or negated entry (including negated zero).
			continue
		}

		// Index j was on work queue, meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is L-type, queue k for processing later in this loop.
		// If k-1 is S-type (text[k-1] < text[k]), queue -k to save for the caller.
		// If k is zero, k-1 doesn't exist, so we only need to leave it
		// for the caller. The caller can't tell the difference between
		// an empty slot and a non-empty zero, but there's no need
		// to distinguish them anyway: the final suffix array will end up
		// with one zero somewhere, and that will be a real zero.
		k := j - 1
		c1 := text[k]
		if k > 0 {
			if c0 := text[k-1]; c0 < c1 {
				k = -k
			}
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

func induceS_8_64(text []byte, sa, freq, bucket []int64) {
	// Initialize positions for right side of character buckets.
	bucketMax_8_64(text, freq, bucket)
	bucket = bucket[:256] // eliminate bounds check for bucket[cB] below

	cB := byte(0)
	b := bucket[cB]

	for i := len(sa) - 1; i >= 0; i-- {
		j := int(sa[i])
		if j >= 0 {
			// Skip non-flagged entry.
			// (This loop can't see an empty entry; 0 means the real zero index.)
			continue
		}

		// Negative j is a work queue entry; rewrite to positive j for final suffix array.
		j = -j
		sa[i] = int64(j)

		// Index j was on work queue (encoded as -j but now decoded),
		// meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is S-type, queue -k for processing later in this loop.
		// If k-1 is L-type (text[k-1] > text[k]), queue k to save for the caller.
		// If k is zero, k-1 doesn't exist, so we only need to leave it
		// for the caller.
		k := j - 1
		c1 := text[k]
		if k > 0 {
			if c0 := text[k-1]; c0 <= c1 {
				k = -k
			}
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

func induceS_32(text []int32, sa, freq, bucket []int32) {
	// Initialize positions for right side of character buckets.
	bucketMax_32(text, freq, bucket)

	cB := int32(0)
	b := bucket[cB]

	for i := len(sa) - 1; i >= 0; i-- {
		j := int(sa[i])
		if j >= 0 {
			// Skip non-flagged entry.
			// (This loop can't see an empty entry; 0 means the real zero index.)
			continue
		}

		// Negative j is a work queue entry; rewrite to positive j for final suffix array.
		j = -j
		sa[i] = int32(j)

		// Index j was on work queue (encoded as -j but now decoded),
		// meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is S-type, queue -k for processing later in this loop.
		// If k-1 is L-type (text[k-1] > text[k]), queue k to save for the caller.
		// If k is zero, k-1 doesn't exist, so we only need to leave it
		// for the caller.
		k := j - 1
		c1 := text[k]
		if k > 0 {
			if c0 := text[k-1]; c0 <= c1 {
				k = -k
			}
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

func induceS_64(text []int64, sa, freq, bucket []int64) {
	// Initialize positions for right side of character buckets.
	bucketMax_64(text, freq, bucket)

	cB := int64(0)
	b := bucket[cB]

	for i := len(sa) - 1; i >= 0; i-- {
		j := int(sa[i])
		if j >= 0 {
			// Skip non-flagged entry.
			// (This loop can't see an empty entry; 0 means the real zero index.)
			continue
		}

		// Negative j is a work queue entry; rewrite to positive j for final suffix array.
		j = -j
		sa[i] = int64(j)

		// Index j was on work queue (encoded as -j but now decoded),
		// meaning k := j-1 is L-type,
		// so we can now place k correctly into sa.
		// If k-1 is S-type, queue -k for processing later in this loop.
		// If k-1 is L-type (text[k-1] > text[k]), queue k to save for the caller.
		// If k is zero, k-1 doesn't exist, so we only need to leave it
		// for the caller.
		k := j - 1
		c1 := text[k]
		if k > 0 {
			if c0 := text[k-1]; c0 <= c1 {
				k = -k
			}
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

"""




```