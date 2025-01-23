Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The core request is to analyze a Go file (`filter.go`) related to profiling and explain its functionality, demonstrate its usage, and identify potential pitfalls. The emphasis is on filtering profile data.

**2. Initial Code Scan - Identifying Key Structures and Functions:**

The first step is to quickly scan the code and identify the main data structures and functions. I see:

* **`Profile` struct (implicitly):**  The functions are methods on a `Profile` struct (though the struct definition itself isn't shown). This immediately suggests the code is about manipulating profiling data.
* **Filtering Functions:**  Several functions have names starting with "Filter" (`FilterSamplesByName`, `FilterTagsByName`, `FilterSamplesByTag`). This is a strong indicator of the primary purpose.
* **Matching Functions:** Functions like `matchesName`, `unmatchedLines`, `matchedLines`, `lastMatchedLineIndex` suggest the use of regular expressions for pattern matching within the profile data.
* **`ShowFrom` function:** This function seems different, dealing with truncating stack frames.
* **Regular Expressions (`regexp.Regexp`):**  The frequent use of `*regexp.Regexp` highlights the importance of regular expressions in the filtering process.

**3. Analyzing Individual Functions - Functionality and Purpose:**

Now, I'll go through each function and try to understand its specific role:

* **`FilterSamplesByName`:**  This is a key function. It filters samples based on whether their location names (function names, file names, mapping file names) match `focus` or `ignore` regular expressions. The `hide` and `show` parameters further refine which *lines* within a location are kept. The logic involving `focusOrIgnore` and `hidden` needs careful attention. It seems to keep samples that match `focus` and *don't* match `ignore`. `hide` removes matching lines, and if all lines are removed, the location is hidden. `show` keeps only matching lines and hides the location if no lines match.

* **`ShowFrom`:** This function is about trimming stack traces. It keeps frames from the first occurrence of a frame matching `showFrom` down to the leaf. The example provided in the code's comments is very helpful for understanding this.

* **`filterShowFromLocation`:** This is a helper function for `ShowFrom`, checking if a location or its mapping matches the `showFrom` regex and potentially truncating lines within the location.

* **`lastMatchedLineIndex`:** Another helper, finding the last line within a location that matches a given regex.

* **`FilterTagsByName`:** This filters tags (labels and numerical labels) associated with samples based on `show` and `hide` regular expressions.

* **`matchesName`:**  A utility function to check if a location's information matches a regex.

* **`unmatchedLines`:** Returns lines that *don't* match a regex.

* **`matchedLines`:** Returns lines that *do* match a regex.

* **`focusedAndNotIgnored`:**  A helper for `FilterSamplesByName`, determining if a sample's locations meet the focus and ignore criteria.

* **`FilterSamplesByTag`:** This function filters samples based on custom `TagMatch` functions, providing more flexible filtering logic based on sample tags.

**4. Identifying Core Go Features:**

Based on the function analysis, I can identify the main Go features demonstrated:

* **Methods on Structs:** The filtering functions are methods of the `Profile` struct, illustrating object-oriented programming principles in Go.
* **Regular Expressions:** The `regexp` package is heavily used for pattern matching.
* **Slices and Maps:**  Slices (`[]*Sample`, `[]*Location`, `[]Line`) and maps (`map[uint64]bool`, `map[string]string`, `map[string]int64`) are used for data storage and manipulation.
* **Functions as Arguments (Higher-Order Functions):** `FilterSamplesByTag` takes `TagMatch` as an argument, which is a function type. This demonstrates the use of higher-order functions.

**5. Crafting Examples and Explanations:**

Now, I can start constructing examples to illustrate the functionality. For each filtering function, I'll:

* **Define a sample `Profile` (mock data):** This will involve creating `Sample`, `Location`, `Line`, and `Function` structs with relevant data.
* **Demonstrate the function call:**  Show how to use the filtering function with specific regular expressions or `TagMatch` functions.
* **Show the input and output:**  Illustrate how the profile is modified after the filtering operation.

**6. Identifying Potential Pitfalls:**

This requires thinking about how users might misuse the functions:

* **Incorrect Regular Expressions:**  The most common issue. Users might write regexes that don't match what they expect, leading to unexpected filtering results.
* **Misunderstanding `focus` and `ignore` logic:** It's important to clarify that a sample is kept if it matches `focus` *and* does not match `ignore`.
* **`hide` and `show` interaction:**  Users might not understand how these modify the *lines* within a location.
* **`ShowFrom` behavior with no matches:**  Emphasize that if `showFrom` doesn't match, the sample is dropped.
* **Case sensitivity of regexes:** This is a common regex gotcha.

**7. Structuring the Answer:**

Finally, I organize the information into a clear and comprehensive answer, addressing each part of the original request:

* **Functionality List:**  A bulleted list summarizing the purpose of each function.
* **Go Feature Demonstration:**  Code examples for key features like regular expressions and methods.
* **Code Reasoning Example:**  A detailed example for one of the filtering functions (`FilterSamplesByName`), including input, function call, and output.
* **Command-Line Parameter Explanation:** Explain how these filters are typically used with command-line tools like `pprof`.
* **Common Mistakes:**  A section highlighting potential user errors with examples.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe I should explain the `Profile` struct in detail. **Correction:**  Since the code doesn't provide the struct definition, it's better to focus on the functions and their behavior, assuming a basic understanding of profiling data.
* **Initial thought:**  Provide a very complex example for each function. **Correction:**  Simpler, focused examples are more effective for illustrating the core functionality.
* **Initial thought:**  Just list the potential pitfalls. **Correction:** Providing concrete examples of these mistakes makes the explanation much clearer.

By following this systematic approach, breaking down the code into manageable parts, and focusing on clarity and practical examples, I can arrive at a comprehensive and helpful explanation of the provided Go code.
这段代码是 Go 语言 `pprof` 工具的一部分，位于 `profile` 包中，主要功能是**过滤性能剖析数据（profile）中的样本 (samples)**。它提供了一系列的函数，允许用户根据函数名、文件名、标签 (tags) 等条件来选择或排除特定的样本，从而帮助用户更专注于他们感兴趣的性能瓶颈。

下面我们来详细列举一下它的功能：

**核心功能:**

1. **`FilterSamplesByName(focus, ignore, hide, show *regexp.Regexp) (fm, im, hm, hnm bool)`:**
   - **功能:** 根据函数名、文件名以及映射文件名过滤样本。
   - **`focus` (聚焦):**  只保留至少有一个栈帧匹配 `focus` 正则表达式的样本。如果 `focus` 为 `nil`，则表示匹配所有样本（除非被 `ignore` 排除）。
   - **`ignore` (忽略):** 排除任何有栈帧匹配 `ignore` 正则表达式的样本。
   - **`hide` (隐藏行):** 对于匹配 `hide` 正则表达式的 Location，移除匹配的行信息。如果一个 Location 的所有行都被隐藏，则该 Location 将被排除在样本之外。
   - **`show` (显示行):** 对于 Location，只保留匹配 `show` 正则表达式的行信息。如果一个 Location 没有行匹配 `show`，则该 Location 将被排除在样本之外。
   - **返回值:**
     - `fm`:  `focus` 正则表达式是否匹配了至少一个样本。
     - `im`:  `ignore` 正则表达式是否匹配了至少一个样本。
     - `hm`:  `hide` 正则表达式是否匹配了至少一个 Location。
     - `hnm`: `show` 正则表达式是否匹配了至少一个 Location 的行。

2. **`ShowFrom(showFrom *regexp.Regexp) (matched bool)`:**
   - **功能:**  从匹配指定正则表达式的栈帧开始显示。它会移除样本中高于第一个匹配 `showFrom` 正则表达式的栈帧。
   - **`showFrom`:** 一个正则表达式，用于指定要开始显示的栈帧。
   - **返回值:** `matched`，表示是否找到了匹配的栈帧。如果 `showFrom` 为 `nil`，则返回 `false` 并且不修改 profile。

3. **`FilterTagsByName(show, hide *regexp.Regexp) (sm, hm bool)`:**
   - **功能:** 根据标签名过滤样本的标签。
   - **`show` (显示标签):**  只保留标签名匹配 `show` 正则表达式的标签。如果 `show` 为 `nil`，则保留所有标签（除非被 `hide` 排除）。
   - **`hide` (隐藏标签):** 移除标签名匹配 `hide` 正则表达式的标签。
   - **返回值:**
     - `sm`: `show` 正则表达式是否匹配了至少一个标签。
     - `hm`: `hide` 正则表达式是否匹配了至少一个标签。

4. **`FilterSamplesByTag(focus, ignore TagMatch) (fm, im bool)`:**
   - **功能:** 使用自定义的 `TagMatch` 函数来过滤样本。
   - **`focus` (聚焦):** 一个 `TagMatch` 函数，如果返回 `true`，则保留该样本。如果为 `nil`，则视为所有样本都匹配。
   - **`ignore` (忽略):** 一个 `TagMatch` 函数，如果返回 `true`，则排除该样本。
   - **返回值:**
     - `fm`:  `focus` 函数是否匹配了至少一个样本。
     - `im`:  `ignore` 函数是否匹配了至少一个样本。

**辅助功能:**

- **`matchesName(re *regexp.Regexp) bool`:**  判断一个 `Location` 是否匹配给定的正则表达式，检查函数名、文件名以及映射文件名。
- **`unmatchedLines(re *regexp.Regexp) []Line`:** 返回 `Location` 中不匹配给定正则表达式的行信息。
- **`matchedLines(re *regexp.Regexp) []Line`:** 返回 `Location` 中匹配给定正则表达式的行信息。
- **`lastMatchedLineIndex(re *regexp.Regexp) int`:** 返回 `Location` 中最后一个匹配给定正则表达式的行的索引，如果没有匹配则返回 -1。
- **`focusedAndNotIgnored(locs []*Location, m map[uint64]bool) bool`:** 内部辅助函数，用于判断一个样本是否满足 `focus` 且不满足 `ignore` 的条件。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 **方法 (Methods)** 和 **结构体 (Structs)** 的概念，以及 **正则表达式 (Regular Expressions)** 的使用。它定义了一些方法绑定到 `Profile` 结构体上，用于修改 `Profile` 结构体内部的 `Sample` 和 `Location` 数据。

**Go 代码举例说明:**

假设我们有以下简化的 `Profile` 结构体和一些样本数据：

```go
package profile

import "regexp"

type Function struct {
	Name     string
	Filename string
}

type Line struct {
	Function *Function
}

type Location struct {
	ID      uint64
	Line    []Line
	Mapping *Mapping // 假设存在 Mapping 结构体
}

type Mapping struct {
	File string
}

type Sample struct {
	Location []*Location
	Label    map[string]string
	NumLabel map[string]int64
}

type Profile struct {
	Sample   []*Sample
	Location []*Location
}

// ... (这里包含了上面提供的 filter.go 中的代码)

func main() {
	p := &Profile{
		Sample: []*Sample{
			{
				Location: []*Location{
					{ID: 1, Line: []Line{{Function: &Function{Name: "foo", Filename: "file1.go"}}}},
					{ID: 2, Line: []Line{{Function: &Function{Name: "bar", Filename: "file2.go"}}}},
				},
				Label: map[string]string{"user": "alice"},
			},
			{
				Location: []*Location{
					{ID: 3, Line: []Line{{Function: &Function{Name: "baz", Filename: "file3.go"}}}},
				},
				Label: map[string]string{"user": "bob"},
			},
			{
				Location: []*Location{
					{ID: 4, Line: []Line{{Function: &Function{Name: "qux", Filename: "file1.go"}}}},
					{ID: 5, Line: []Line{{Function: &Function{Name: "foo", Filename: "file1.go"}}}},
				},
				Label: map[string]string{"user": "alice"},
			},
		},
		Location: []*Location{
			{ID: 1, Line: []Line{{Function: &Function{Name: "foo", Filename: "file1.go"}}}},
			{ID: 2, Line: []Line{{Function: &Function{Name: "bar", Filename: "file2.go"}}}},
			{ID: 3, Line: []Line{{Function: &Function{Name: "baz", Filename: "file3.go"}}}},
			{ID: 4, Line: []Line{{Function: &Function{Name: "qux", Filename: "file1.go"}}}},
			{ID: 5, Line: []Line{{Function: &Function{Name: "foo", Filename: "file1.go"}}}},
		},
	}

	// 使用 FilterSamplesByName 过滤包含 "foo" 但不包含 "bar" 的样本
	focus := regexp.MustCompile("foo")
	ignore := regexp.MustCompile("bar")
	p.FilterSamplesByName(focus, ignore, nil, nil)
	println("After FilterSamplesByName (focus: foo, ignore: bar):")
	for _, s := range p.Sample {
		print("  Sample Locations: ")
		for _, loc := range s.Location {
			print(loc.Line[0].Function.Name, " ")
		}
		println()
	}

	// 使用 ShowFrom 过滤，只显示从 "bar" 开始的栈帧
	p = &Profile{ // 重新加载数据，因为上面的过滤会修改 p
		Sample: []*Sample{
			{
				Location: []*Location{
					{ID: 1, Line: []Line{{Function: &Function{Name: "foo", Filename: "file1.go"}}}},
					{ID: 2, Line: []Line{{Function: &Function{Name: "bar", Filename: "file2.go"}}}},
					{ID: 3, Line: []Line{{Function: &Function{Name: "baz", Filename: "file3.go"}}}},
				},
			},
		},
		Location: []*Location{
			{ID: 1, Line: []Line{{Function: &Function{Name: "foo", Filename: "file1.go"}}}},
			{ID: 2, Line: []Line{{Function: &Function{Name: "bar", Filename: "file2.go"}}}},
			{ID: 3, Line: []Line{{Function: &Function{Name: "baz", Filename: "file3.go"}}}},
		},
	}
	showFrom := regexp.MustCompile("bar")
	p.ShowFrom(showFrom)
	println("After ShowFrom (showFrom: bar):")
	for _, s := range p.Sample {
		print("  Sample Locations: ")
		for _, loc := range s.Location {
			print(loc.Line[0].Function.Name, " ")
		}
		println()
	}

	// 使用 FilterTagsByName 过滤，只显示 "user" 标签
	p = &Profile{ // 重新加载数据
		Sample: []*Sample{
			{Label: map[string]string{"user": "alice", "type": "cpu"}},
			{Label: map[string]string{"user": "bob"}},
		},
	}
	showTag := regexp.MustCompile("user")
	p.FilterTagsByName(showTag, nil)
	println("After FilterTagsByName (show: user):")
	for _, s := range p.Sample {
		println("  Sample Labels:", s.Label)
	}
}
```

**假设的输入与输出:**

**`FilterSamplesByName` 示例:**

* **输入:** 上面的 `p`，`focus` 为 `"foo"`，`ignore` 为 `"bar"`。
* **输出:** `p.Sample` 将只包含第一个和第三个样本，因为它们包含 "foo" 且不包含 "bar"。
   ```
   After FilterSamplesByName (focus: foo, ignore: bar):
     Sample Locations: foo bar
     Sample Locations: qux foo
   ```

**`ShowFrom` 示例:**

* **输入:** 上面的 `p` (重新加载后的)，`showFrom` 为 `"bar"`。
* **输出:** `p.Sample` 中的样本的 Location 将被截断，只保留从 "bar" 开始的栈帧。
   ```
   After ShowFrom (showFrom: bar):
     Sample Locations: bar baz
   ```

**`FilterTagsByName` 示例:**

* **输入:** 上面的 `p` (重新加载后的)，`showTag` 为 `"user"`。
* **输出:** `p.Sample` 中的标签将只保留 "user" 标签。
   ```
   After FilterTagsByName (show: user):
     Sample Labels: map[user:alice]
     Sample Labels: map[user:bob]
   ```

**命令行参数的具体处理:**

这段代码本身是 Go 库的一部分，并不直接处理命令行参数。然而，`pprof` 工具作为一个命令行程序，会使用这些函数来实现其过滤功能。通常，`pprof` 会提供类似以下的命令行选项来利用这些过滤功能：

* **`-focus=<regexp>` 或 `--functions=<regexp>`:**  对应 `FilterSamplesByName` 的 `focus` 参数，用于指定要关注的函数或文件名。
* **`-ignore=<regexp>` 或 `--ignore_functions=<regexp>`:** 对应 `FilterSamplesByName` 的 `ignore` 参数，用于指定要忽略的函数或文件名。
* **`-hide=<regexp>` 或 `--hide_functions=<regexp>`:** 对应 `FilterSamplesByName` 的 `hide` 参数，用于隐藏匹配的行。
* **`-show=<regexp>` 或 `--show_functions=<regexp>`:** 对应 `FilterSamplesByName` 的 `show` 参数，用于只显示匹配的行。
* **`-show_from=<regexp>`:** 对应 `ShowFrom` 的 `showFrom` 参数，用于指定开始显示的栈帧。
* **`--tagfocus=<regexp>`:** 对应 `FilterTagsByName` 的 `show` 参数，用于指定要关注的标签。
* **`--tagignore=<regexp>`:** 对应 `FilterTagsByName` 的 `hide` 参数，用于指定要忽略的标签。

例如，在 `pprof` 命令行中：

```bash
go tool pprof -focus='^net/http\.' my_profile.pb.gz
```

这个命令会加载 `my_profile.pb.gz` 文件，并使用正则表达式 `^net/http\.` 过滤，只显示函数名以 `net/http.` 开头的样本。

```bash
go tool pprof -ignore='_test\.go$' my_profile.pb.gz
```

这个命令会忽略文件名以 `_test.go` 结尾的样本。

**使用者易犯错的点:**

1. **正则表达式错误:** 这是最常见的问题。用户可能不熟悉正则表达式的语法，导致过滤条件与预期不符。例如，忘记转义特殊字符，或者使用了错误的锚点 (`^` 和 `$`)。

   **示例:**  用户想要忽略所有包含 "test" 的函数，可能会写成 `-ignore=test`，但这会匹配到任何包含 "test" 子串的函数名，而不仅仅是整个单词 "test"。正确的写法可能是 `-ignore='\btest\b'` (使用单词边界)。

2. **对 `focus` 和 `ignore` 的理解偏差:** 用户可能会认为 `focus` 和 `ignore` 是互斥的，但实际上，只有当一个样本**至少有一个栈帧匹配 `focus` 并且没有栈帧匹配 `ignore`** 时才会被保留。

   **示例:**  如果用户同时设置了 `-focus='foo'` 和 `-ignore='bar'`，那么只有包含 "foo" 但不包含 "bar" 的调用栈才会被保留。如果一个调用栈既包含 "foo" 又包含 "bar"，则会被排除。

3. **不理解 `hide` 和 `show` 对行的影响:**  用户可能认为 `hide` 和 `show` 会直接排除 Location，但实际上它们是作用于 Location 内部的行信息。只有当 `hide` 移除了 Location 的所有行，或者 `show` 导致 Location 没有行匹配时，该 Location 才会被间接排除。

   **示例:**  使用 `-hide='.*'` 会隐藏所有行的信息，导致大多数 Location 变为空，从而间接地移除了这些 Location 对应的样本信息。

4. **`ShowFrom` 的使用不当:** 用户可能期望 `ShowFrom` 能够显示多个匹配的栈帧，但它只会从**第一个**匹配的栈帧开始显示。如果 `showFrom` 没有匹配到任何栈帧，整个样本将会被移除。

总而言之，`go/src/cmd/vendor/github.com/google/pprof/profile/filter.go` 这部分代码为 `pprof` 工具提供了强大的样本过滤能力，帮助用户根据不同的需求分析性能数据。理解其各个过滤函数的作用和参数是高效使用 `pprof` 的关键。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/profile/filter.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package profile

// Implements methods to filter samples from profiles.

import "regexp"

// FilterSamplesByName filters the samples in a profile and only keeps
// samples where at least one frame matches focus but none match ignore.
// Returns true is the corresponding regexp matched at least one sample.
func (p *Profile) FilterSamplesByName(focus, ignore, hide, show *regexp.Regexp) (fm, im, hm, hnm bool) {
	if focus == nil && ignore == nil && hide == nil && show == nil {
		fm = true // Missing focus implies a match
		return
	}
	focusOrIgnore := make(map[uint64]bool)
	hidden := make(map[uint64]bool)
	for _, l := range p.Location {
		if ignore != nil && l.matchesName(ignore) {
			im = true
			focusOrIgnore[l.ID] = false
		} else if focus == nil || l.matchesName(focus) {
			fm = true
			focusOrIgnore[l.ID] = true
		}

		if hide != nil && l.matchesName(hide) {
			hm = true
			l.Line = l.unmatchedLines(hide)
			if len(l.Line) == 0 {
				hidden[l.ID] = true
			}
		}
		if show != nil {
			l.Line = l.matchedLines(show)
			if len(l.Line) == 0 {
				hidden[l.ID] = true
			} else {
				hnm = true
			}
		}
	}

	s := make([]*Sample, 0, len(p.Sample))
	for _, sample := range p.Sample {
		if focusedAndNotIgnored(sample.Location, focusOrIgnore) {
			if len(hidden) > 0 {
				var locs []*Location
				for _, loc := range sample.Location {
					if !hidden[loc.ID] {
						locs = append(locs, loc)
					}
				}
				if len(locs) == 0 {
					// Remove sample with no locations (by not adding it to s).
					continue
				}
				sample.Location = locs
			}
			s = append(s, sample)
		}
	}
	p.Sample = s

	return
}

// ShowFrom drops all stack frames above the highest matching frame and returns
// whether a match was found. If showFrom is nil it returns false and does not
// modify the profile.
//
// Example: consider a sample with frames [A, B, C, B], where A is the root.
// ShowFrom(nil) returns false and has frames [A, B, C, B].
// ShowFrom(A) returns true and has frames [A, B, C, B].
// ShowFrom(B) returns true and has frames [B, C, B].
// ShowFrom(C) returns true and has frames [C, B].
// ShowFrom(D) returns false and drops the sample because no frames remain.
func (p *Profile) ShowFrom(showFrom *regexp.Regexp) (matched bool) {
	if showFrom == nil {
		return false
	}
	// showFromLocs stores location IDs that matched ShowFrom.
	showFromLocs := make(map[uint64]bool)
	// Apply to locations.
	for _, loc := range p.Location {
		if filterShowFromLocation(loc, showFrom) {
			showFromLocs[loc.ID] = true
			matched = true
		}
	}
	// For all samples, strip locations after the highest matching one.
	s := make([]*Sample, 0, len(p.Sample))
	for _, sample := range p.Sample {
		for i := len(sample.Location) - 1; i >= 0; i-- {
			if showFromLocs[sample.Location[i].ID] {
				sample.Location = sample.Location[:i+1]
				s = append(s, sample)
				break
			}
		}
	}
	p.Sample = s
	return matched
}

// filterShowFromLocation tests a showFrom regex against a location, removes
// lines after the last match and returns whether a match was found. If the
// mapping is matched, then all lines are kept.
func filterShowFromLocation(loc *Location, showFrom *regexp.Regexp) bool {
	if m := loc.Mapping; m != nil && showFrom.MatchString(m.File) {
		return true
	}
	if i := loc.lastMatchedLineIndex(showFrom); i >= 0 {
		loc.Line = loc.Line[:i+1]
		return true
	}
	return false
}

// lastMatchedLineIndex returns the index of the last line that matches a regex,
// or -1 if no match is found.
func (loc *Location) lastMatchedLineIndex(re *regexp.Regexp) int {
	for i := len(loc.Line) - 1; i >= 0; i-- {
		if fn := loc.Line[i].Function; fn != nil {
			if re.MatchString(fn.Name) || re.MatchString(fn.Filename) {
				return i
			}
		}
	}
	return -1
}

// FilterTagsByName filters the tags in a profile and only keeps
// tags that match show and not hide.
func (p *Profile) FilterTagsByName(show, hide *regexp.Regexp) (sm, hm bool) {
	matchRemove := func(name string) bool {
		matchShow := show == nil || show.MatchString(name)
		matchHide := hide != nil && hide.MatchString(name)

		if matchShow {
			sm = true
		}
		if matchHide {
			hm = true
		}
		return !matchShow || matchHide
	}
	for _, s := range p.Sample {
		for lab := range s.Label {
			if matchRemove(lab) {
				delete(s.Label, lab)
			}
		}
		for lab := range s.NumLabel {
			if matchRemove(lab) {
				delete(s.NumLabel, lab)
			}
		}
	}
	return
}

// matchesName returns whether the location matches the regular
// expression. It checks any available function names, file names, and
// mapping object filename.
func (loc *Location) matchesName(re *regexp.Regexp) bool {
	for _, ln := range loc.Line {
		if fn := ln.Function; fn != nil {
			if re.MatchString(fn.Name) || re.MatchString(fn.Filename) {
				return true
			}
		}
	}
	if m := loc.Mapping; m != nil && re.MatchString(m.File) {
		return true
	}
	return false
}

// unmatchedLines returns the lines in the location that do not match
// the regular expression.
func (loc *Location) unmatchedLines(re *regexp.Regexp) []Line {
	if m := loc.Mapping; m != nil && re.MatchString(m.File) {
		return nil
	}
	var lines []Line
	for _, ln := range loc.Line {
		if fn := ln.Function; fn != nil {
			if re.MatchString(fn.Name) || re.MatchString(fn.Filename) {
				continue
			}
		}
		lines = append(lines, ln)
	}
	return lines
}

// matchedLines returns the lines in the location that match
// the regular expression.
func (loc *Location) matchedLines(re *regexp.Regexp) []Line {
	if m := loc.Mapping; m != nil && re.MatchString(m.File) {
		return loc.Line
	}
	var lines []Line
	for _, ln := range loc.Line {
		if fn := ln.Function; fn != nil {
			if !re.MatchString(fn.Name) && !re.MatchString(fn.Filename) {
				continue
			}
		}
		lines = append(lines, ln)
	}
	return lines
}

// focusedAndNotIgnored looks up a slice of ids against a map of
// focused/ignored locations. The map only contains locations that are
// explicitly focused or ignored. Returns whether there is at least
// one focused location but no ignored locations.
func focusedAndNotIgnored(locs []*Location, m map[uint64]bool) bool {
	var f bool
	for _, loc := range locs {
		if focus, focusOrIgnore := m[loc.ID]; focusOrIgnore {
			if focus {
				// Found focused location. Must keep searching in case there
				// is an ignored one as well.
				f = true
			} else {
				// Found ignored location. Can return false right away.
				return false
			}
		}
	}
	return f
}

// TagMatch selects tags for filtering
type TagMatch func(s *Sample) bool

// FilterSamplesByTag removes all samples from the profile, except
// those that match focus and do not match the ignore regular
// expression.
func (p *Profile) FilterSamplesByTag(focus, ignore TagMatch) (fm, im bool) {
	samples := make([]*Sample, 0, len(p.Sample))
	for _, s := range p.Sample {
		focused, ignored := true, false
		if focus != nil {
			focused = focus(s)
		}
		if ignore != nil {
			ignored = ignore(s)
		}
		fm = fm || focused
		im = im || ignored
		if focused && !ignored {
			samples = append(samples, s)
		}
	}
	p.Sample = samples
	return
}
```