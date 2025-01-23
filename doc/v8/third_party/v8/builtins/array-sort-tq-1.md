Response:
My thought process for analyzing the provided Torque code (`array-sort.tq`) went like this:

1. **Identify the Core Functionality:** The filename "array-sort.tq" and the presence of functions like `ArrayTimSortImpl`, `MergeCollapse`, `MergeAt`, etc., strongly suggest this code implements the array sorting functionality for V8. The mention of "TimSort" confirms this.

2. **Recognize Torque:** The `.tq` extension and the syntax (`transitioning macro`, `implicit context: Context`, `Smi`, `JSAny`) clearly indicate this is V8's Torque language. This means it's low-level code that interacts directly with V8's internal data structures.

3. **Break Down the Code into Key Sections (Macros and Builtins):**

    * **Macros (Smaller Reusable Units):** I looked for `transitioning macro`. These are likely helper functions or logical blocks within the sorting algorithm. I noted functions like `CountAndMakeRun`, `BinaryInsertionSort`, `MergeLow`, `MergeHigh`, `ComputeMinRunLength`, `RunInvariantEstablished`, `MergeCollapse`, `MergeForceCollapse`, `CompactReceiverElementsIntoWorkArray`, and `CopyWorkArrayToReceiver`. I started to infer their roles based on their names and parameters (e.g., `MergeLow` and `MergeHigh` likely handle merging sorted runs).

    * **Builtins (Entry Points):** I searched for `transitioning builtin` and `transitioning javascript builtin`. These are the functions directly exposed to JavaScript or other parts of V8. `ArrayTimSort` seemed like the central TimSort implementation, and `ArrayPrototypeSort` looked like the JavaScript-accessible `Array.prototype.sort` method.

4. **Infer the Algorithm (TimSort):** The presence of concepts like "runs," "minimum run length," "galloping," and the names of the merge functions strongly pointed to TimSort, a hybrid merge sort and insertion sort algorithm.

5. **Connect Torque Code to JavaScript Behavior:**  I considered how the lower-level Torque code would manifest in JavaScript. The `ArrayPrototypeSort` builtin directly relates to the `sort()` method in JavaScript. The comparison function argument, the in-place sorting behavior, and the handling of `undefined` and holes are key aspects of JavaScript's `sort()` that I looked for in the Torque code.

6. **Analyze Individual Macros for Specific Functionality:**  I examined the logic within each macro:

    * **Run Creation (`CountAndMakeRun`):**  Identifies naturally sorted sequences.
    * **Small Run Handling (`BinaryInsertionSort`):**  Optimizes sorting for small subarrays.
    * **Merging (`MergeLow`, `MergeHigh`):**  The core of the merge sort, handling merging from the beginning and end of subarrays. The galloping optimization was a significant detail.
    * **Run Length Management (`ComputeMinRunLength`):**  Determines the optimal minimum run length for TimSort.
    * **Stack Management (`MergeCollapse`, `MergeForceCollapse`):** Manages the merging of sorted runs to maintain efficiency.
    * **Handling `undefined` and Holes (`CompactReceiverElementsIntoWorkArray`, `CopyWorkArrayToReceiver`):**  This is crucial for understanding how JavaScript's `sort()` handles sparse arrays and `undefined` values.

7. **Relate to Potential User Errors:** Based on my understanding of JavaScript's `sort()`, I considered common errors:
    * **Incorrect Comparison Function:**  Returning incorrect values (< 0, 0, > 0) or inconsistent comparisons.
    * **Non-Callable Comparison Function:**  Passing something other than a function as the comparison argument.
    * **Side Effects in Comparison Function:** Modifying the array being sorted within the comparison function (though the code tries to detect this).

8. **Construct Example Inputs and Outputs:**  To illustrate the logic, I devised simple JavaScript examples showing how the `sort()` method would behave with different inputs and a custom comparison function.

9. **Synthesize and Summarize:**  Finally, I organized my findings into a clear and concise summary, covering the main functionalities, the connection to JavaScript, illustrative examples, and common user errors. I made sure to address the specific prompt's requirements (listing functionalities, using JavaScript examples, providing input/output, and discussing common errors). The "Part 2" aspect reminded me to focus on summarizing the overall functionality based on the provided code snippet.
这是 `v8/third_party/v8/builtins/array-sort.tq` 源代码的第二部分，它延续了第一部分关于数组排序的实现。基于你提供的代码片段，我们可以归纳一下它的功能：

**核心功能归纳：**

这部分代码主要实现了 TimSort 算法的关键合并（merge）步骤，用于高效地合并已排序的子数组，并包含一些辅助功能来优化排序过程。

**详细功能点：**

1. **`MergeLow(baseA, lengthAArg, baseB, lengthBArg)`:**  实现从左向右稳定合并两个相邻的已排序子数组。
    * 它使用一个临时数组 (`tempArray`) 来存储较短的子数组，以减少元素的移动。
    * 它实现了“galloping”模式，当一个子数组连续多次“获胜”（根据比较函数），会进入快速移动模式，跳过多个元素，以加速合并。
    * 如果一个子数组完全合并完，它会将另一个子数组剩余的部分复制过来。

2. **`MergeHigh(baseA, lengthAArg, baseB, lengthBArg)`:** 实现从右向左稳定合并两个相邻的已排序子数组。
    * 类似于 `MergeLow`，但它是从数组的末尾开始合并。
    * 同样使用了临时数组和 galloping 模式。
    * 适用于需要将较大的已排序子数组合并到较小数组前面的情况。

3. **`ComputeMinRunLength(nArg)`:** 计算 TimSort 算法中最小运行长度（minrun）。
    * 短于这个长度的自然有序子数组会被扩展，通过插入排序使其达到最小长度，以提高后续合并的效率。
    * 这个函数基于数组的长度 `n` 返回一个合适的 `minRunLength`。

4. **`RunInvariantEstablished(pendingRuns, n)`:** 检查待合并的已排序子数组栈（`pendingRuns`）是否满足 TimSort 的运行不变量。
    * 这些不变量（例如，`run_length(i - 3) > run_length(i - 2) + run_length(i - 1)`）确保了合并操作的效率。

5. **`MergeCollapse(context, sortState)`:**  检查并合并待合并栈中的子数组，直到重新满足运行不变量。
    * 它会比较栈顶的几个子数组的长度，并根据不变量选择合适的相邻子数组进行合并。

6. **`MergeForceCollapse(context, sortState)`:** 强制合并待合并栈中的所有子数组，直到只剩下一个已排序的数组。
    * 这通常在 TimSort 的最后阶段执行。

7. **`ArrayTimSortImpl(context, sortState, length)`:**  实现 TimSort 算法的核心逻辑。
    * 它遍历数组，找到自然有序的子数组（runs）。
    * 如果找到的 run 太短，会使用二分插入排序将其扩展到 `minRunLength`。
    * 将找到的或扩展的 run 压入待合并栈 (`pendingRuns`)。
    * 调用 `MergeCollapse` 来维护栈的不变量并进行合并。
    * 最后，调用 `MergeForceCollapse` 合并剩余的 run。

8. **`CompactReceiverElementsIntoWorkArray(isToSorted)`:** 将接收器（要排序的数组）中的有效元素（非 `undefined` 或 hole）复制到一个工作数组 (`workArray`) 中。
    * 对于 `Array.prototype.sort`，hole 会被忽略，元素会被紧凑地放在工作数组的前面。
    * 对于 `Array.prototype.toSorted`，`undefined` 值也会被计算在内。
    * 返回非 `undefined` 元素的数量。

9. **`CopyWorkArrayToReceiver(numberOfNonUndefined)`:** 将工作数组中已排序的元素复制回接收器。
    * 将排序后的元素放回原数组。
    * 根据需要添加 `undefined` 值。
    * 根据接收器的类型（例如，是否是稀疏数组），删除或设置为 hole 剩余的索引。

10. **`ArrayTimSort(context, sortState)`:**  作为 TimSort 的入口点，协调整个排序过程。
    * 调用 `CompactReceiverElementsIntoWorkArray` 将有效元素放入工作数组。
    * 调用 `ArrayTimSortImpl` 执行 TimSort 算法。
    * 检查在排序过程中接收器是否被修改，如果被修改则切换到慢速路径。
    * 调用 `CopyWorkArrayToReceiver` 将排序结果写回接收器。

11. **`ArrayPrototypeSort(receiver, ...arguments)`:**  `Array.prototype.sort` 的内置实现（javascript builtin）。
    * 获取可选的比较函数 `comparefn`。
    * 将接收器转换为对象。
    * 获取数组的长度。
    * 创建 `SortState` 对象来管理排序状态。
    * 调用 `ArrayTimSort` 执行排序。
    * 返回排序后的对象。

**与 Javascript 功能的关系及举例说明：**

`v8/third_party/v8/builtins/array-sort.tq` 中定义的 `ArrayPrototypeSort` 直接对应 JavaScript 中 `Array.prototype.sort()` 方法的功能。

**JavaScript 示例：**

```javascript
const arr = [3, 1, 4, 1, 5, 9, 2, 6];

// 使用默认排序（将元素转换为字符串后进行比较）
arr.sort();
console.log(arr); // 输出: [1, 1, 2, 3, 4, 5, 6, 9]

// 使用自定义比较函数进行数字排序
arr.sort((a, b) => a - b);
console.log(arr); // 输出: [1, 1, 2, 3, 4, 5, 6, 9]

const objects = [{value: 3}, {value: 1}, {value: 4}];
objects.sort((a, b) => a.value - b.value);
console.log(objects); // 输出: [{value: 1}, {value: 3}, {value: 4}]
```

**代码逻辑推理（假设输入与输出）：**

假设我们有一个数组 `[5, 2, 8, 1]`，并且没有提供比较函数。

1. **`CompactReceiverElementsIntoWorkArray`:** 将数组元素复制到工作数组 `workArray`。
2. **`ArrayTimSortImpl`:**
   - 找到初始 runs：`[5]`, `[2, 8]`, `[1]`。
   - `ComputeMinRunLength` 计算出的最小运行长度可能为 2 或 3。
   - 如果 minRunLength 是 2，则 `[1]` 会被二分插入排序扩展为 `[1]` 或与其他元素合并。
   - `MergeCollapse` 会根据 run 的长度合并相邻的 runs。例如，可能会先合并 `[2, 8]` 和 `[1]` 得到 `[1, 2, 8]`，然后再与 `[5]` 合并。
3. **`MergeLow` 或 `MergeHigh`:** 执行具体的合并操作，例如合并 `[5]` 和 `[1, 2, 8]` 时，会比较 `5` 和 `1`，然后将 `1` 放入结果，以此类推。
4. **`CopyWorkArrayToReceiver`:** 将排序后的数组 `[1, 2, 5, 8]` 写回原数组。

**用户常见的编程错误：**

1. **比较函数返回非数字值或不一致的值：**

   ```javascript
   const arr = [3, 1, 4];
   arr.sort((a, b) => {
       if (a > b) return "大于"; // 错误：返回字符串
       if (a < b) return -1;
       return 0;
   }); // 可能会抛出错误或导致不正确的排序
   ```

2. **比较函数中修改了正在排序的数组：** 这会导致不可预测的行为，TimSort 的实现可能会在排序过程中检查这种情况。

   ```javascript
   const arr = [3, 1, 4];
   arr.sort((a, b) => {
       arr.push(0); // 错误：修改了正在排序的数组
       return a - b;
   });
   ```

3. **忘记处理 `undefined` 值或数组中的 holes：**  虽然 TimSort 内部会处理，但在自定义比较函数中不注意可能会导致错误。

   ```javascript
   const arr = [3, undefined, 1];
   arr.sort((a, b) => a - b); // 错误：undefined 与数字比较可能出错
   ```

**总结 `array-sort.tq` 的功能（基于提供的代码片段）：**

这部分 `array-sort.tq` 代码的核心功能是实现了高效的 TimSort 算法，用于在 V8 引擎中对 JavaScript 数组进行排序。它包含了合并已排序子数组的关键逻辑（`MergeLow` 和 `MergeHigh`），以及用于优化排序过程的辅助功能，如计算最小运行长度、维护运行不变量、以及将数组元素复制到工作数组和写回接收器。`ArrayPrototypeSort` 方法作为 JavaScript `Array.prototype.sort()` 的底层实现，使得 V8 能够高效地执行数组排序操作。

### 提示词
```
这是目录为v8/third_party/v8/builtins/array-sort.tq的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/v8/builtins/array-sort.tq以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
ts[cursorB]),
            UnsafeCast<JSAny>(tempArray.objects[cursorTemp]));

        if (order < 0) {
          workArray.objects[dest++] = workArray.objects[cursorB++];

          ++nofWinsB;
          --lengthB;
          nofWinsA = 0;

          if (lengthB == 0) goto Succeed;
          if (nofWinsB >= minGallop) break;
        } else {
          workArray.objects[dest++] = tempArray.objects[cursorTemp++];

          ++nofWinsA;
          --lengthA;
          nofWinsB = 0;

          if (lengthA == 1) goto CopyB;
          if (nofWinsA >= minGallop) break;
        }
      }

      // One run is winning so consistently that galloping may be a huge
      // win. So try that, and continue galloping until (if ever) neither
      // run appears to be winning consistently anymore.
      ++minGallop;
      let firstIteration: bool = true;
      while (nofWinsA >= kMinGallopWins || nofWinsB >= kMinGallopWins ||
             firstIteration) {
        firstIteration = false;
        dcheck(lengthA > 1 && lengthB > 0);

        minGallop = SmiMax(1, minGallop - 1);
        sortState.minGallop = minGallop;

        nofWinsA = GallopRight(
            tempArray, UnsafeCast<JSAny>(workArray.objects[cursorB]),
            cursorTemp, lengthA, 0);
        dcheck(nofWinsA >= 0);

        if (nofWinsA > 0) {
          Copy(tempArray, cursorTemp, workArray, dest, nofWinsA);
          dest = dest + nofWinsA;
          cursorTemp = cursorTemp + nofWinsA;
          lengthA = lengthA - nofWinsA;

          if (lengthA == 1) goto CopyB;

          // lengthA == 0 is impossible now if the comparison function is
          // consistent, but we can't assume that it is.
          if (lengthA == 0) goto Succeed;
        }
        workArray.objects[dest++] = workArray.objects[cursorB++];
        if (--lengthB == 0) goto Succeed;

        nofWinsB = GallopLeft(
            workArray, UnsafeCast<JSAny>(tempArray.objects[cursorTemp]),
            cursorB, lengthB, 0);
        dcheck(nofWinsB >= 0);
        if (nofWinsB > 0) {
          Copy(workArray, cursorB, workArray, dest, nofWinsB);

          dest = dest + nofWinsB;
          cursorB = cursorB + nofWinsB;
          lengthB = lengthB - nofWinsB;

          if (lengthB == 0) goto Succeed;
        }
        workArray.objects[dest++] = tempArray.objects[cursorTemp++];
        if (--lengthA == 1) goto CopyB;
      }
      ++minGallop;  // Penalize it for leaving galloping mode
      sortState.minGallop = minGallop;
    }
  } label Succeed {
    if (lengthA > 0) {
      Copy(tempArray, cursorTemp, workArray, dest, lengthA);
    }
  } label CopyB {
    dcheck(lengthA == 1 && lengthB > 0);
    // The last element of run A belongs at the end of the merge.
    Copy(workArray, cursorB, workArray, dest, lengthB);
    workArray.objects[dest + lengthB] = tempArray.objects[cursorTemp];
  }
}

// Merge the lengthA elements starting at baseA with the lengthB elements
// starting at baseB in a stable way, in-place. lengthA and lengthB must
// be > 0. Must also have that array[baseA + lengthA - 1] belongs at the
// end of the merge and should have lengthA >= lengthB.
transitioning macro MergeHigh(
    implicit context: Context, sortState: SortState)(baseA: Smi,
    lengthAArg: Smi, baseB: Smi, lengthBArg: Smi): void {
  dcheck(0 < lengthAArg && 0 < lengthBArg);
  dcheck(0 <= baseA && 0 < baseB);
  dcheck(baseA + lengthAArg == baseB);

  let lengthA: Smi = lengthAArg;
  let lengthB: Smi = lengthBArg;

  const workArray = sortState.workArray;
  const tempArray: FixedArray = GetTempArray(sortState, lengthB);
  Copy(workArray, baseB, tempArray, 0, lengthB);

  // MergeHigh merges the two runs backwards.
  let dest: Smi = baseB + lengthB - 1;
  let cursorTemp: Smi = lengthB - 1;
  let cursorA: Smi = baseA + lengthA - 1;

  workArray.objects[dest--] = workArray.objects[cursorA--];

  try {
    if (--lengthA == 0) goto Succeed;
    if (lengthB == 1) goto CopyA;

    let minGallop: Smi = sortState.minGallop;
    // TODO(szuend): Replace with something that does not have a runtime
    //               overhead as soon as its available in Torque.
    while (Int32TrueConstant()) {
      let nofWinsA: Smi = 0;  // # of times A won in a row.
      let nofWinsB: Smi = 0;  // # of times B won in a row.

      // Do the straightforward thing until (if ever) one run appears to
      // win consistently.
      // TODO(szuend): Replace with something that does not have a runtime
      //               overhead as soon as its available in Torque.
      while (Int32TrueConstant()) {
        dcheck(lengthA > 0 && lengthB > 1);

        const order = sortState.Compare(
            UnsafeCast<JSAny>(tempArray.objects[cursorTemp]),
            UnsafeCast<JSAny>(workArray.objects[cursorA]));

        if (order < 0) {
          workArray.objects[dest--] = workArray.objects[cursorA--];

          ++nofWinsA;
          --lengthA;
          nofWinsB = 0;

          if (lengthA == 0) goto Succeed;
          if (nofWinsA >= minGallop) break;
        } else {
          workArray.objects[dest--] = tempArray.objects[cursorTemp--];

          ++nofWinsB;
          --lengthB;
          nofWinsA = 0;

          if (lengthB == 1) goto CopyA;
          if (nofWinsB >= minGallop) break;
        }
      }

      // One run is winning so consistently that galloping may be a huge
      // win. So try that, and continue galloping until (if ever) neither
      // run appears to be winning consistently anymore.
      ++minGallop;
      let firstIteration: bool = true;
      while (nofWinsA >= kMinGallopWins || nofWinsB >= kMinGallopWins ||
             firstIteration) {
        firstIteration = false;

        dcheck(lengthA > 0 && lengthB > 1);

        minGallop = SmiMax(1, minGallop - 1);
        sortState.minGallop = minGallop;

        let k: Smi = GallopRight(
            workArray, UnsafeCast<JSAny>(tempArray.objects[cursorTemp]), baseA,
            lengthA, lengthA - 1);
        dcheck(k >= 0);
        nofWinsA = lengthA - k;

        if (nofWinsA > 0) {
          dest = dest - nofWinsA;
          cursorA = cursorA - nofWinsA;
          Copy(workArray, cursorA + 1, workArray, dest + 1, nofWinsA);

          lengthA = lengthA - nofWinsA;
          if (lengthA == 0) goto Succeed;
        }
        workArray.objects[dest--] = tempArray.objects[cursorTemp--];
        if (--lengthB == 1) goto CopyA;

        k = GallopLeft(
            tempArray, UnsafeCast<JSAny>(workArray.objects[cursorA]), 0,
            lengthB, lengthB - 1);
        dcheck(k >= 0);
        nofWinsB = lengthB - k;

        if (nofWinsB > 0) {
          dest = dest - nofWinsB;
          cursorTemp = cursorTemp - nofWinsB;
          Copy(tempArray, cursorTemp + 1, workArray, dest + 1, nofWinsB);

          lengthB = lengthB - nofWinsB;
          if (lengthB == 1) goto CopyA;

          // lengthB == 0 is impossible now if the comparison function is
          // consistent, but we can't assume that it is.
          if (lengthB == 0) goto Succeed;
        }
        workArray.objects[dest--] = workArray.objects[cursorA--];
        if (--lengthA == 0) goto Succeed;
      }
      ++minGallop;
      sortState.minGallop = minGallop;
    }
  } label Succeed {
    if (lengthB > 0) {
      dcheck(lengthA == 0);
      Copy(tempArray, 0, workArray, dest - (lengthB - 1), lengthB);
    }
  } label CopyA {
    dcheck(lengthB == 1 && lengthA > 0);

    // The first element of run B belongs at the front of the merge.
    dest = dest - lengthA;
    cursorA = cursorA - lengthA;
    Copy(workArray, cursorA + 1, workArray, dest + 1, lengthA);
    workArray.objects[dest] = tempArray.objects[cursorTemp];
  }
}

// Compute a good value for the minimum run length; natural runs shorter
// than this are boosted artificially via binary insertion sort.
//
// If n < 64, return n (it's too small to bother with fancy stuff).
// Else if n is an exact power of 2, return 32.
// Else return an int k, 32 <= k <= 64, such that n/k is close to, but
// strictly less than, an exact power of 2.
//
// See listsort.txt for more info.
macro ComputeMinRunLength(nArg: Smi): Smi {
  let n: Smi = nArg;
  let r: Smi = 0;  // Becomes 1 if any 1 bits are shifted off.

  dcheck(n >= 0);
  while (n >= 64) {
    r = r | (n & 1);
    n = n >> 1;
  }

  const minRunLength: Smi = n + r;
  dcheck(nArg < 64 || (32 <= minRunLength && minRunLength <= 64));
  return minRunLength;
}

// Returns true iff run_length(n - 2) > run_length(n - 1) + run_length(n).
macro RunInvariantEstablished(
    implicit context: Context)(pendingRuns: FixedArray, n: Smi): bool {
  if (n < 2) return true;

  const runLengthN: Smi = GetPendingRunLength(pendingRuns, n);
  const runLengthNM: Smi = GetPendingRunLength(pendingRuns, n - 1);
  const runLengthNMM: Smi = GetPendingRunLength(pendingRuns, n - 2);

  return runLengthNMM > runLengthNM + runLengthN;
}

// Examines the stack of runs waiting to be merged, merging adjacent runs
// until the stack invariants are re-established:
//
//   1. run_length(i - 3) > run_length(i - 2) + run_length(i - 1)
//   2. run_length(i - 2) > run_length(i - 1)
//
// TODO(szuend): Remove unnecessary loads. This macro was refactored to
//               improve readability, introducing unnecessary loads in the
//               process. Determine if all these extra loads are ok.
transitioning macro MergeCollapse(context: Context, sortState: SortState):
    void {
  const pendingRuns: FixedArray = sortState.pendingRuns;

  // Reload the stack size because MergeAt might change it.
  while (GetPendingRunsSize(sortState) > 1) {
    let n: Smi = GetPendingRunsSize(sortState) - 2;

    if (!RunInvariantEstablished(pendingRuns, n + 1) ||
        !RunInvariantEstablished(pendingRuns, n)) {
      if (GetPendingRunLength(pendingRuns, n - 1) <
          GetPendingRunLength(pendingRuns, n + 1)) {
        --n;
      }

      MergeAt(n);
    } else if (
        GetPendingRunLength(pendingRuns, n) <=
        GetPendingRunLength(pendingRuns, n + 1)) {
      MergeAt(n);
    } else {
      break;
    }
  }
}

// Regardless of invariants, merge all runs on the stack until only one
// remains. This is used at the end of the mergesort.
transitioning macro MergeForceCollapse(context: Context, sortState: SortState):
    void {
  const pendingRuns: FixedArray = sortState.pendingRuns;

  // Reload the stack size becuase MergeAt might change it.
  while (GetPendingRunsSize(sortState) > 1) {
    let n: Smi = GetPendingRunsSize(sortState) - 2;

    if (n > 0 &&
        GetPendingRunLength(pendingRuns, n - 1) <
            GetPendingRunLength(pendingRuns, n + 1)) {
      --n;
    }
    MergeAt(n);
  }
}

transitioning macro ArrayTimSortImpl(
    context: Context, sortState: SortState, length: Smi): void {
  if (length < 2) return;
  let remaining: Smi = length;

  // March over the array once, left to right, finding natural runs,
  // and extending short natural runs to minrun elements.
  let low: Smi = 0;
  const minRunLength: Smi = ComputeMinRunLength(remaining);
  while (remaining != 0) {
    let currentRunLength: Smi = CountAndMakeRun(low, low + remaining);

    // If the run is short, extend it to min(minRunLength, remaining).
    if (currentRunLength < minRunLength) {
      const forcedRunLength: Smi = SmiMin(minRunLength, remaining);
      BinaryInsertionSort(low, low + currentRunLength, low + forcedRunLength);
      currentRunLength = forcedRunLength;
    }

    // Push run onto pending-runs stack, and maybe merge.
    PushRun(sortState, low, currentRunLength);

    MergeCollapse(context, sortState);

    // Advance to find next run.
    low = low + currentRunLength;
    remaining = remaining - currentRunLength;
  }

  MergeForceCollapse(context, sortState);
  dcheck(GetPendingRunsSize(sortState) == 1);
  dcheck(GetPendingRunLength(sortState.pendingRuns, 0) == length);
}

transitioning macro CompactReceiverElementsIntoWorkArray(
    implicit context: Context, sortState: SortState)(
    isToSorted: constexpr bool): Smi {
  let growableWorkArray = growable_fixed_array::GrowableFixedArray{
    array: sortState.workArray,
    capacity: Convert<intptr>(sortState.workArray.length),
    length: 0
  };

  const loadFn = sortState.loadFn;

  // TODO(szuend): Implement full range sorting, not only up to MaxSmi.
  //               https://crbug.com/v8/7970.
  const receiverLength: Number = sortState.initialReceiverLength;
  dcheck(IsNumberNormalized(receiverLength));

  const sortLength: Smi = TaggedIsSmi(receiverLength) ?
      UnsafeCast<Smi>(receiverLength) :
      Convert<PositiveSmi>(kSmiMax) otherwise unreachable;

  // Move all non-undefined elements into {sortState.workArray}, holes
  // are ignored.
  let numberOfUndefined: Smi = 0;
  for (let i: Smi = 0; i < receiverLength; ++i) {
    const element: JSAny|TheHole = loadFn(context, sortState, i);

    if (element == TheHole) {
      if constexpr (isToSorted) {
        // Array.prototype.toSorted does not have the HasProperty check that
        // Array.prototype.sort has and unconditionally performs a GetProperty
        // for each element.
        //
        // Only fast JSArray accessors return TheHole, and fast JSArrays are
        // protected by the NoElements protector which ensures that objects on
        // the prototype chain do not have indexed properties. So if a fast
        // JSArray accessor returns TheHole, we know the prototype walk will
        // return Undefined.

        numberOfUndefined++;
      } else {
        // Do nothing for holes for Array.prototype.sort. The result
        // is that elements are compacted at the front of the work array.
      }
    } else if (element == Undefined) {
      numberOfUndefined++;
    } else {
      growableWorkArray.Push(element);
    }
  }

  // Reset the workArray on the frameState, as it may have grown.
  sortState.workArray = growableWorkArray.array;
  sortState.sortLength = sortLength;
  sortState.numberOfUndefined = numberOfUndefined;

  return Convert<Smi>(growableWorkArray.length);
}

transitioning macro CopyWorkArrayToReceiver(
    implicit context: Context, sortState: SortState)(
    numberOfNonUndefined: Smi): void {
  const storeFn = sortState.storeFn;
  const workArray = sortState.workArray;

  dcheck(numberOfNonUndefined <= workArray.length);
  dcheck(
      numberOfNonUndefined + sortState.numberOfUndefined <=
      sortState.sortLength);

  // Writing the elements back is a 3 step process:
  //   1. Copy the sorted elements from the workarray to the receiver.
  //   2. Add {nOfUndefined} undefineds to the receiver.
  //   3. Depending on the backing store either delete properties or
  //      set them to the TheHole up to {sortState.sortLength}.
  let index: Smi = 0;
  for (; index < numberOfNonUndefined; ++index) {
    storeFn(
        context, sortState, index, UnsafeCast<JSAny>(workArray.objects[index]));
  }

  const numberOfUndefinedEnd: Smi =
      sortState.numberOfUndefined + numberOfNonUndefined;
  for (; index < numberOfUndefinedEnd; ++index) {
    storeFn(context, sortState, index, Undefined);
  }

  const end: Smi = sortState.sortLength;
  const deleteFn = sortState.deleteFn;
  for (; index < end; ++index) {
    deleteFn(context, sortState, index);
  }
}

transitioning builtin ArrayTimSort(context: Context, sortState: SortState):
    JSAny {
  const isToSorted: constexpr bool = false;
  const numberOfNonUndefined: Smi =
      CompactReceiverElementsIntoWorkArray(isToSorted);
  ArrayTimSortImpl(context, sortState, numberOfNonUndefined);

  try {
    // The comparison function or toString might have changed the
    // receiver, if that is the case, we switch to the slow path.
    sortState.CheckAccessor() otherwise Slow;
  } label Slow deferred {
    sortState.ResetToGenericAccessor(isToSorted);
  }

  CopyWorkArrayToReceiver(numberOfNonUndefined);
  return kSuccess;
}

// https://tc39.github.io/ecma262/#sec-array.prototype.sort
transitioning javascript builtin ArrayPrototypeSort(
    js-implicit context: NativeContext, receiver: JSAny)(...arguments): JSAny {
  // 1. If comparefn is not undefined and IsCallable(comparefn) is false,
  //    throw a TypeError exception.
  const comparefnObj: JSAny = arguments[0];
  const comparefn = Cast<(Undefined | Callable)>(comparefnObj) otherwise
  ThrowTypeError(MessageTemplate::kBadSortComparisonFunction, comparefnObj);

  // 2. Let obj be ? ToObject(this value).
  const obj: JSReceiver = ToObject(context, receiver);

  // 3. Let len be ? ToLength(? Get(obj, "length")).
  const len: Number = GetLengthProperty(obj);

  if (len < 2) return obj;

  const isToSorted: constexpr bool = false;
  const sortState: SortState = NewSortState(obj, comparefn, len, isToSorted);
  ArrayTimSort(context, sortState);

  return obj;
}
}
```