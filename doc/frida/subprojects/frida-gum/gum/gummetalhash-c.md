Response:
Let's break down the thought process for analyzing the `gummetalhash.c` source code and generating the comprehensive response.

**1. Initial Understanding & Goal Identification:**

The first step is to grasp the fundamental purpose of the code. The file name `gummetalhash.c` strongly suggests it's an implementation of a hash table, likely optimized or designed for specific use within the Frida framework (given the `frida` and `gum` prefixes). The prompt asks for its functionalities, relationship to reverse engineering, interaction with low-level concepts, logical reasoning, common errors, and debugging context. This provides a clear roadmap for the analysis.

**2. High-Level Code Scan & Structure Recognition:**

Next, I quickly scanned the code to identify key components and their relationships. I looked for:

* **Data Structures:** `GumMetalHashTable` and `RealIter` stand out as the core data structures. I noted their members and what kind of information they hold (size, keys, values, hash values, iteration state).
* **Function Signatures:** I paid attention to the function names and their parameters. Functions like `gum_metal_hash_table_new`, `insert`, `lookup`, `remove`, `iter_init`, `iter_next`, etc., are typical hash table operations.
* **Key Algorithms/Techniques:**  I spotted the use of prime numbers (`prime_mod`), bitwise operations for masking (`mask`), and the presence of "tombstones." These hint at specific hash table implementation details, like collision resolution strategies (likely quadratic probing, given the `step++`).
* **Memory Management:**  The use of `gum_internal_malloc`, `gum_internal_free`, and `gum_internal_calloc` indicates custom memory management, a common practice in performance-critical libraries. The `ref_count` member signals reference counting for memory management.

**3. Functionality Extraction (Instruction #2):**

Based on the high-level scan, I started listing the core functionalities provided by the hash table:

* **Creation/Destruction:** `gum_metal_hash_table_new`, `gum_metal_hash_table_new_full`, `gum_metal_hash_table_destroy`, `gum_metal_hash_table_unref`.
* **Insertion/Updating:** `gum_metal_hash_table_insert`, `gum_metal_hash_table_replace`, `gum_metal_hash_table_add`.
* **Lookup:** `gum_metal_hash_table_lookup`, `gum_metal_hash_table_lookup_extended`, `gum_metal_hash_table_contains`, `gum_metal_hash_table_find`.
* **Deletion:** `gum_metal_hash_table_remove`, `gum_metal_hash_table_steal`, `gum_metal_hash_table_remove_all`, `gum_metal_hash_table_steal_all`, `gum_metal_hash_table_foreach_remove`, `gum_metal_hash_table_foreach_steal`.
* **Iteration:** `gum_metal_hash_table_iter_init`, `gum_metal_hash_table_iter_next`, `gum_metal_hash_table_iter_remove`, `gum_metal_hash_table_iter_replace`, `gum_metal_hash_table_iter_steal`.
* **Size:** `gum_metal_hash_table_size`.
* **Reference Counting:** `gum_metal_hash_table_ref`, `gum_metal_hash_table_unref`.

**4. Reverse Engineering Relevance (Instruction #3):**

I considered how a hash table like this would be used in the context of dynamic instrumentation and reverse engineering:

* **Storing Hook Information:** Frida needs to keep track of where hooks are placed and what code they execute. Hash tables are excellent for mapping addresses to hook handlers or original instructions.
* **Managing Runtime State:**  During instrumentation, Frida might need to store and retrieve information associated with specific program states or objects. Hash tables provide efficient lookups based on memory addresses or other identifiers.
* **Symbol Resolution:**  Mapping symbol names to their addresses is a crucial task in reverse engineering. Hash tables are a standard data structure for symbol tables.

I then crafted specific examples illustrating these uses.

**5. Low-Level Concepts (Instruction #4):**

I analyzed the code for interactions with low-level concepts:

* **Binary Level:** The core purpose of a hash table—mapping keys to values—directly relates to how data is organized and accessed in memory. The code manipulates pointers (`gpointer`).
* **Linux/Android Kernel:** While this specific file might not directly interact with kernel code, I knew Frida itself operates at a low level. Hash tables are used within operating system kernels for various purposes (e.g., process management, file system metadata). I connected this to Frida's ability to hook into system calls and kernel functions.
* **Android Framework:** Similarly, hash tables are prevalent in the Android framework for managing components, services, and resources. I pointed out Frida's ability to hook into Android framework APIs.
* **Memory Management:** The custom memory allocation functions and reference counting are key low-level aspects. I explained their importance for performance and preventing memory leaks.
* **Bitwise Operations:** The use of bitwise shifts and AND operations for calculating table size and indices are classic low-level optimizations.

**6. Logical Reasoning (Instruction #5):**

For demonstrating logical reasoning, I chose a simple scenario: inserting and retrieving a key-value pair. I provided the assumed input to `gum_metal_hash_table_insert` and the expected output from `gum_metal_hash_table_lookup`. This shows how the hash table's internal logic would function in a basic case.

**7. Common Usage Errors (Instruction #6):**

I brainstormed common mistakes developers might make when using a hash table:

* **Incorrect Hash/Equality Functions:** This is a classic problem leading to incorrect lookups or lost data.
* **Memory Management Issues:** Forgetting to unref the hash table or destroying keys/values prematurely can cause crashes or leaks.
* **Concurrent Access Issues:** Hash tables are generally not thread-safe by default, so concurrent access without proper synchronization can lead to data corruption.
* **Modifying Keys:** Changing a key after it's been inserted can lead to the hash table becoming inconsistent.

I provided illustrative code examples for each of these errors.

**8. Debugging Context (Instruction #7):**

To illustrate how one might end up in this code during debugging, I outlined a realistic Frida usage scenario: writing a script to hook a function and then investigating issues. I described the steps involved in setting up the hook, observing unexpected behavior, and then potentially drilling down into the `gummetalhash.c` code to understand how Frida is managing its internal data structures.

**9. Review and Refinement:**

Finally, I reviewed the entire response to ensure it was accurate, comprehensive, well-organized, and addressed all aspects of the prompt. I checked for clarity, consistency, and any potential misunderstandings. For example, I made sure to clearly distinguish between the functionalities and how they relate to the other requested aspects like reverse engineering and low-level details.
This is the source code for `gummetalhash.c`, a hash table implementation used within the Frida dynamic instrumentation toolkit. Let's break down its functionalities and its relevance to reverse engineering, low-level concepts, logical reasoning, potential errors, and debugging.

**Functionalities of `gummetalhash.c`:**

This file implements a generic hash table data structure. Its core functionalities include:

1. **Creation and Destruction:**
   - `gum_metal_hash_table_new()`: Creates a new, empty hash table with default hash and key equality functions.
   - `gum_metal_hash_table_new_full()`: Creates a new, empty hash table allowing specification of custom hash, key equality, key destruction, and value destruction functions.
   - `gum_metal_hash_table_destroy()`: Destroys a hash table, freeing all its associated memory and calling the key and value destroy functions (if provided).
   - `gum_metal_hash_table_ref()`: Increments the reference count of a hash table.
   - `gum_metal_hash_table_unref()`: Decrements the reference count of a hash table, and destroys it when the count reaches zero.

2. **Insertion and Updating:**
   - `gum_metal_hash_table_insert()`: Inserts a new key-value pair into the hash table. If the key already exists, the old value is replaced.
   - `gum_metal_hash_table_replace()`: Inserts a new key-value pair, replacing the existing value if the key exists. It keeps the new key provided.
   - `gum_metal_hash_table_add()`: Adds a new key to the hash table. If the key already exists, nothing happens. The key also acts as its value.

3. **Lookup:**
   - `gum_metal_hash_table_lookup()`: Retrieves the value associated with a given key. Returns `NULL` if the key is not found.
   - `gum_metal_hash_table_lookup_extended()`: Retrieves the value associated with a given key, and optionally retrieves the original key as it was stored in the table.
   - `gum_metal_hash_table_contains()`: Checks if a given key exists in the hash table.
   - `gum_metal_hash_table_find()`: Iterates through the hash table and returns the value of the first key-value pair for which a provided predicate function returns `TRUE`.

4. **Deletion:**
   - `gum_metal_hash_table_remove()`: Removes a key-value pair from the hash table, calling the key and value destroy functions (if provided).
   - `gum_metal_hash_table_steal()`: Removes a key-value pair from the hash table *without* calling the key and value destroy functions. This is useful when the caller wants to take ownership of the key and value.
   - `gum_metal_hash_table_remove_all()`: Removes all key-value pairs from the hash table, calling the key and value destroy functions.
   - `gum_metal_hash_table_steal_all()`: Removes all key-value pairs without calling the key and value destroy functions.
   - `gum_metal_hash_table_foreach_remove()`: Iterates through the hash table and removes key-value pairs for which a provided function returns `TRUE`, calling the destroy functions.
   - `gum_metal_hash_table_foreach_steal()`: Similar to `foreach_remove`, but does not call the destroy functions.

5. **Iteration:**
   - `gum_metal_hash_table_iter_init()`: Initializes an iterator for traversing the hash table.
   - `gum_metal_hash_table_iter_next()`: Advances the iterator to the next key-value pair.
   - `gum_metal_hash_table_iter_get_hash_table()`: Returns the hash table associated with an iterator.
   - `gum_metal_hash_table_iter_remove()`: Removes the current key-value pair from the hash table using the iterator (calls destroy functions).
   - `gum_metal_hash_table_iter_replace()`: Replaces the value of the current key-value pair using the iterator.
   - `gum_metal_hash_table_iter_steal()`: Removes the current key-value pair without calling the destroy functions.

6. **Size:**
   - `gum_metal_hash_table_size()`: Returns the number of key-value pairs in the hash table.

7. **Internal Management:**
   - The code includes functions for resizing the hash table (`gum_metal_hash_table_resize`), calculating hash indices (`gum_metal_hash_table_lookup_node`), and managing internal data structures.

**Relationship to Reverse Engineering:**

Hash tables are fundamental data structures used extensively in reverse engineering tools and techniques. `gummetalhash.c` directly facilitates Frida's ability to:

* **Store Hook Information:** Frida needs to keep track of where hooks are placed in memory and the associated handler functions. Hash tables are a natural fit for mapping memory addresses (the "key") to hook details (the "value").
    * **Example:** When you use `Interceptor.attach(address, { onEnter: ..., onLeave: ... })`, Frida likely uses a hash table where `address` is the key, and the `onEnter` and `onLeave` callbacks are part of the value.

* **Manage Runtime State:** During instrumentation, Frida might need to store and retrieve information associated with specific program states, thread contexts, or object instances. Hash tables allow efficient lookup based on identifiers.
    * **Example:** If Frida is tracking allocations, it might use a hash table to map allocated memory addresses to allocation metadata (size, allocation time, etc.).

* **Implement Caches:**  Frida could use hash tables to cache results of expensive operations, such as resolving function addresses or parsing data structures.

* **Symbol Resolution:**  While not directly implemented in this file, hash tables are the backbone of symbol tables. Frida likely uses them (potentially from other libraries) to map function and variable names to their memory addresses.

**In the context of Frida:**

Imagine you are using Frida to hook a function in a target application. When the target application calls that function, Frida intercepts the execution. Internally, Frida needs to quickly find the hook handler you provided. This is where the hash table comes into play.

1. When you attach a hook, Frida calculates a hash of the function's address.
2. This hash is used to find the appropriate entry in the hash table.
3. The value associated with that entry contains the details of your hook handler (the `onEnter` and `onLeave` callbacks).

**Relevance to Binary Bottom, Linux, Android Kernel and Framework:**

* **Binary Bottom:** Hash tables operate on memory addresses and raw data. The keys and values stored within this hash table are ultimately pointers to locations in the target process's memory. The hash function itself operates on the binary representation of the keys.

* **Linux/Android Kernel:** While this specific code is likely part of Frida's user-space component, hash tables are also heavily used within the Linux and Android kernels for various purposes:
    * **Process Management:** Mapping process IDs (PIDs) to process structures.
    * **File System:** Mapping file names to inode numbers.
    * **Networking:** Mapping socket addresses to socket structures.
    * Frida, when interacting with the kernel (e.g., through system call interception), might rely on or interact with kernel-level hash tables.

* **Android Framework:** The Android framework extensively uses hash tables (often through Java's `HashMap` or native implementations) to manage components, services, and resources. Frida, when hooking into Android applications, interacts with these framework-level hash tables indirectly. For example, when you hook a method in an Android class, Frida might be manipulating data structures that internally rely on hash tables.

**Logical Reasoning (Hypothetical Input and Output):**

Let's assume:

* `hash_table` is a newly created `GumMetalHashTable`.
* `key1` is a pointer to a string "hello".
* `value1` is a pointer to an integer `123`.
* `key2` is a pointer to a string "world".
* `value2` is a pointer to an integer `456`.

**Input:**

```c
gum_metal_hash_table_insert(hash_table, key1, value1);
gum_metal_hash_table_insert(hash_table, key2, value2);
gpointer retrieved_value = gum_metal_hash_table_lookup(hash_table, key1);
```

**Output:**

`retrieved_value` will point to the same memory location as `value1` (the integer `123`).

**Explanation:**

1. The first `gum_metal_hash_table_insert` call will calculate a hash of `key1` ("hello") and store the key-value pair in the hash table.
2. The second `gum_metal_hash_table_insert` call does the same for `key2` ("world").
3. The `gum_metal_hash_table_lookup` call will calculate the hash of `key1` again and use it to find the corresponding entry in the hash table, returning the associated `value1`.

**Common Usage Errors:**

Users (or Frida's internal components) can make several errors when using this hash table implementation:

1. **Incorrect Hash or Equality Functions:** If the `hash_func` doesn't distribute keys well or the `key_equal_func` doesn't correctly determine if two keys are equal, the hash table will not function correctly. Lookups might fail, or multiple "equal" keys might be inserted.
    * **Example:** If a custom `hash_func` always returns the same value for different keys, all entries will collide in the same slot, severely impacting performance and potentially leading to incorrect behavior.

2. **Memory Management Issues:** If custom destroy functions (`key_destroy_func`, `value_destroy_func`) are provided, failing to handle memory deallocation correctly within those functions can lead to memory leaks or double frees.
    * **Example:**  If `key_destroy_func` calls `free()` on a key that was allocated on the stack, it will lead to a crash.

3. **Modifying Keys After Insertion:**  If the key object is mutable and is modified after being inserted into the hash table, its hash value might change, making it impossible to find using the original key.
    * **Example:** If you insert a string pointer as a key, and then modify the contents of that string, the hash table might not be able to find the entry anymore.

4. **Concurrent Access Without Synchronization:** This hash table implementation, like many standard hash tables, is likely not thread-safe by default. Accessing and modifying it from multiple threads concurrently without proper locking mechanisms can lead to data corruption and crashes.

**User Operation to Reach This Code (Debugging Clue):**

As a Frida user, you would typically not directly interact with `gummetalhash.c`. However, you might encounter this code indirectly during debugging if:

1. **You are developing a Frida gadget or extension in C:** If you are writing native code that integrates with Frida, you might directly use Frida's internal APIs, including the hash table implementation.

2. **You are debugging a complex Frida script that is behaving unexpectedly:**
   - **Scenario:** You have a Frida script that hooks multiple functions and stores information in a global object. You notice that sometimes the lookups in this global object fail.
   - **Debugging Steps:**
     - You might start by logging the keys you are trying to look up and the contents of your global object.
     - If you suspect an issue with how Frida is managing internal data, you might use a debugger (like GDB or lldb) to step through Frida's code.
     - You might set breakpoints in Frida's core functions, and eventually, you could step into functions within `gummetalhash.c` like `gum_metal_hash_table_lookup` or `gum_metal_hash_table_insert` to understand how Frida is storing and retrieving data related to your hooks or script state.
     - You might notice that the hash values are unexpected, or that the equality function is behaving in a way you didn't anticipate, leading you to investigate the implementation details in `gummetalhash.c`.

3. **You are contributing to Frida's development:** If you are working on improving Frida itself, you would be directly working with this code.

In summary, `gummetalhash.c` provides a fundamental building block for Frida's internal operations. Its efficient key-value storage is crucial for managing hooks, runtime state, and other information necessary for dynamic instrumentation. While a typical Frida user won't directly interact with this file, understanding its purpose is essential for comprehending how Frida works under the hood, and it can become relevant during advanced debugging or development scenarios.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gummetalhash.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */

/*
 * MT safe
 */

#include "gummetalhash.h"

#include "gumlibc.h"
#include "gummemory-priv.h"

#define HASH_TABLE_MIN_SHIFT 3

#define UNUSED_HASH_VALUE 0
#define TOMBSTONE_HASH_VALUE 1
#define HASH_IS_UNUSED(h_) ((h_) == UNUSED_HASH_VALUE)
#define HASH_IS_TOMBSTONE(h_) ((h_) == TOMBSTONE_HASH_VALUE)
#define HASH_IS_REAL(h_) ((h_) >= 2)

/**
 * GumMetalHashTable: (skip)
 */
struct _GumMetalHashTable
{
  gint             size;
  gint             mod;
  guint            mask;
  gint             nnodes;
  gint             noccupied;

  gpointer        *keys;
  guint           *hashes;
  gpointer        *values;

  GHashFunc        hash_func;
  GEqualFunc       key_equal_func;
  gint             ref_count;
  GDestroyNotify   key_destroy_func;
  GDestroyNotify   value_destroy_func;
};

typedef struct
{
  GumMetalHashTable  *hash_table;
  gpointer     dummy1;
  gpointer     dummy2;
  int          position;
  gboolean     dummy3;
  int          version;
} RealIter;

static const gint prime_mod [] =
{
  1,
  2,
  3,
  7,
  13,
  31,
  61,
  127,
  251,
  509,
  1021,
  2039,
  4093,
  8191,
  16381,
  32749,
  65521,
  131071,
  262139,
  524287,
  1048573,
  2097143,
  4194301,
  8388593,
  16777213,
  33554393,
  67108859,
  134217689,
  268435399,
  536870909,
  1073741789,
  2147483647
};

#define gum_metal_new0(struct_type, n_structs) \
    (struct_type *) gum_internal_calloc (n_structs, sizeof (struct_type))

static void
gum_metal_hash_table_set_shift (GumMetalHashTable *hash_table, gint shift)
{
  gint i;
  guint mask = 0;

  hash_table->size = 1 << shift;
  hash_table->mod  = prime_mod [shift];

  for (i = 0; i < shift; i++)
    {
      mask <<= 1;
      mask |= 1;
    }

  hash_table->mask = mask;
}

static gint
gum_metal_hash_table_find_closest_shift (gint n)
{
  gint i;

  for (i = 0; n; i++)
    n >>= 1;

  return i;
}

static void
gum_metal_hash_table_set_shift_from_size (GumMetalHashTable *hash_table, gint size)
{
  gint shift;

  shift = gum_metal_hash_table_find_closest_shift (size);
  shift = MAX (shift, HASH_TABLE_MIN_SHIFT);

  gum_metal_hash_table_set_shift (hash_table, shift);
}

static inline guint
gum_metal_hash_table_lookup_node (GumMetalHashTable    *hash_table,
                          gconstpointer  key,
                          guint         *hash_return)
{
  guint node_index;
  guint node_hash;
  guint hash_value;
  guint first_tombstone = 0;
  gboolean have_tombstone = FALSE;
  guint step = 0;

  hash_value = hash_table->hash_func (key);
  if (G_UNLIKELY (!HASH_IS_REAL (hash_value)))
    hash_value = 2;

  *hash_return = hash_value;

  node_index = hash_value % hash_table->mod;
  node_hash = hash_table->hashes[node_index];

  while (!HASH_IS_UNUSED (node_hash))
    {
      if (node_hash == hash_value)
        {
          gpointer node_key = hash_table->keys[node_index];

          if (hash_table->key_equal_func)
            {
              if (hash_table->key_equal_func (node_key, key))
                return node_index;
            }
          else if (node_key == key)
            {
              return node_index;
            }
        }
      else if (HASH_IS_TOMBSTONE (node_hash) && !have_tombstone)
        {
          first_tombstone = node_index;
          have_tombstone = TRUE;
        }

      step++;
      node_index += step;
      node_index &= hash_table->mask;
      node_hash = hash_table->hashes[node_index];
    }

  if (have_tombstone)
    return first_tombstone;

  return node_index;
}

static void
gum_metal_hash_table_remove_node (GumMetalHashTable   *hash_table,
                          gint          i,
                          gboolean      notify)
{
  gpointer key;
  gpointer value;

  key = hash_table->keys[i];
  value = hash_table->values[i];

  hash_table->hashes[i] = TOMBSTONE_HASH_VALUE;

  hash_table->keys[i] = NULL;
  hash_table->values[i] = NULL;

  hash_table->nnodes--;

  if (notify && hash_table->key_destroy_func)
    hash_table->key_destroy_func (key);

  if (notify && hash_table->value_destroy_func)
    hash_table->value_destroy_func (value);

}

static void
gum_metal_hash_table_remove_all_nodes (GumMetalHashTable *hash_table,
                               gboolean    notify)
{
  int i;
  gpointer key;
  gpointer value;

  hash_table->nnodes = 0;
  hash_table->noccupied = 0;

  if (!notify ||
      (hash_table->key_destroy_func == NULL &&
       hash_table->value_destroy_func == NULL))
    {
      gum_memset (hash_table->hashes, 0, hash_table->size * sizeof (guint));
      gum_memset (hash_table->keys, 0, hash_table->size * sizeof (gpointer));
      gum_memset (hash_table->values, 0, hash_table->size * sizeof (gpointer));

      return;
    }

  for (i = 0; i < hash_table->size; i++)
    {
      if (HASH_IS_REAL (hash_table->hashes[i]))
        {
          key = hash_table->keys[i];
          value = hash_table->values[i];

          hash_table->hashes[i] = UNUSED_HASH_VALUE;
          hash_table->keys[i] = NULL;
          hash_table->values[i] = NULL;

          if (hash_table->key_destroy_func != NULL)
            hash_table->key_destroy_func (key);

          if (hash_table->value_destroy_func != NULL)
            hash_table->value_destroy_func (value);
        }
      else if (HASH_IS_TOMBSTONE (hash_table->hashes[i]))
        {
          hash_table->hashes[i] = UNUSED_HASH_VALUE;
        }
    }
}

static void
gum_metal_hash_table_resize (GumMetalHashTable *hash_table)
{
  gpointer *new_keys;
  gpointer *new_values;
  guint *new_hashes;
  gint old_size;
  gint i;

  old_size = hash_table->size;
  gum_metal_hash_table_set_shift_from_size (hash_table, hash_table->nnodes * 2);

  new_keys = gum_metal_new0 (gpointer, hash_table->size);
  if (hash_table->keys == hash_table->values)
    new_values = new_keys;
  else
    new_values = gum_metal_new0 (gpointer, hash_table->size);
  new_hashes = gum_metal_new0 (guint, hash_table->size);

  for (i = 0; i < old_size; i++)
    {
      guint node_hash = hash_table->hashes[i];
      guint hash_val;
      guint step = 0;

      if (!HASH_IS_REAL (node_hash))
        continue;

      hash_val = node_hash % hash_table->mod;

      while (!HASH_IS_UNUSED (new_hashes[hash_val]))
        {
          step++;
          hash_val += step;
          hash_val &= hash_table->mask;
        }

      new_hashes[hash_val] = hash_table->hashes[i];
      new_keys[hash_val] = hash_table->keys[i];
      new_values[hash_val] = hash_table->values[i];
    }

  if (hash_table->keys != hash_table->values)
    gum_internal_free (hash_table->values);

  gum_internal_free (hash_table->keys);
  gum_internal_free (hash_table->hashes);

  hash_table->keys = new_keys;
  hash_table->values = new_values;
  hash_table->hashes = new_hashes;

  hash_table->noccupied = hash_table->nnodes;
}

static inline void
gum_metal_hash_table_maybe_resize (GumMetalHashTable *hash_table)
{
  gint noccupied = hash_table->noccupied;
  gint size = hash_table->size;

  if ((size > hash_table->nnodes * 4 && size > 1 << HASH_TABLE_MIN_SHIFT) ||
      (size <= noccupied + (noccupied / 16)))
    gum_metal_hash_table_resize (hash_table);
}

GumMetalHashTable *
gum_metal_hash_table_new (GHashFunc  hash_func,
                  GEqualFunc key_equal_func)
{
  return gum_metal_hash_table_new_full (hash_func, key_equal_func, NULL, NULL);
}


GumMetalHashTable *
gum_metal_hash_table_new_full (GHashFunc      hash_func,
                       GEqualFunc     key_equal_func,
                       GDestroyNotify key_destroy_func,
                       GDestroyNotify value_destroy_func)
{
  GumMetalHashTable *hash_table;

  hash_table = gum_internal_malloc (sizeof (GumMetalHashTable));
  gum_metal_hash_table_set_shift (hash_table, HASH_TABLE_MIN_SHIFT);
  hash_table->nnodes             = 0;
  hash_table->noccupied          = 0;
  hash_table->hash_func          = hash_func ? hash_func : g_direct_hash;
  hash_table->key_equal_func     = key_equal_func;
  hash_table->ref_count          = 1;
  hash_table->key_destroy_func   = key_destroy_func;
  hash_table->value_destroy_func = value_destroy_func;
  hash_table->keys               = gum_metal_new0 (gpointer, hash_table->size);
  hash_table->values             = hash_table->keys;
  hash_table->hashes             = gum_metal_new0 (guint, hash_table->size);

  return hash_table;
}

void
gum_metal_hash_table_iter_init (GumMetalHashTableIter *iter,
                        GumMetalHashTable     *hash_table)
{
  RealIter *ri = (RealIter *) iter;

  g_return_if_fail (iter != NULL);
  g_return_if_fail (hash_table != NULL);

  ri->hash_table = hash_table;
  ri->position = -1;
}

gboolean
gum_metal_hash_table_iter_next (GumMetalHashTableIter *iter,
                        gpointer       *key,
                        gpointer       *value)
{
  RealIter *ri = (RealIter *) iter;
  gint position;

  g_return_val_if_fail (iter != NULL, FALSE);
  g_return_val_if_fail (ri->position < ri->hash_table->size, FALSE);

  position = ri->position;

  do
    {
      position++;
      if (position >= ri->hash_table->size)
        {
          ri->position = position;
          return FALSE;
        }
    }
  while (!HASH_IS_REAL (ri->hash_table->hashes[position]));

  if (key != NULL)
    *key = ri->hash_table->keys[position];
  if (value != NULL)
    *value = ri->hash_table->values[position];

  ri->position = position;
  return TRUE;
}

GumMetalHashTable *
gum_metal_hash_table_iter_get_hash_table (GumMetalHashTableIter *iter)
{
  g_return_val_if_fail (iter != NULL, NULL);

  return ((RealIter *) iter)->hash_table;
}

static void
iter_remove_or_steal (RealIter *ri, gboolean notify)
{
  g_return_if_fail (ri != NULL);
  g_return_if_fail (ri->position >= 0);
  g_return_if_fail (ri->position < ri->hash_table->size);

  gum_metal_hash_table_remove_node (ri->hash_table, ri->position, notify);
}

void
gum_metal_hash_table_iter_remove (GumMetalHashTableIter *iter)
{
  iter_remove_or_steal ((RealIter *) iter, TRUE);
}

static gboolean
gum_metal_hash_table_insert_node (GumMetalHashTable *hash_table,
                          guint       node_index,
                          guint       key_hash,
                          gpointer    new_key,
                          gpointer    new_value,
                          gboolean    keep_new_key,
                          gboolean    reusing_key)
{
  gboolean already_exists;
  guint old_hash;
  gpointer key_to_free = NULL;
  gpointer value_to_free = NULL;

  old_hash = hash_table->hashes[node_index];
  already_exists = HASH_IS_REAL (old_hash);

  if (already_exists)
    {
      value_to_free = hash_table->values[node_index];

      if (keep_new_key)
        {
          key_to_free = hash_table->keys[node_index];
          hash_table->keys[node_index] = new_key;
        }
      else
        key_to_free = new_key;
    }
  else
    {
      hash_table->hashes[node_index] = key_hash;
      hash_table->keys[node_index] = new_key;
    }

  if (G_UNLIKELY (hash_table->keys == hash_table->values && hash_table->keys[node_index] != new_value))
    {
      hash_table->values = gum_metal_new0 (gpointer, hash_table->size);
      gum_memcpy (hash_table->values, hash_table->keys, hash_table->size * sizeof (gpointer));
    }

  hash_table->values[node_index] = new_value;

  if (!already_exists)
    {
      hash_table->nnodes++;

      if (HASH_IS_UNUSED (old_hash))
        {
          hash_table->noccupied++;
          gum_metal_hash_table_maybe_resize (hash_table);
        }
    }

  if (already_exists)
    {
      if (hash_table->key_destroy_func && !reusing_key)
        (* hash_table->key_destroy_func) (key_to_free);
      if (hash_table->value_destroy_func)
        (* hash_table->value_destroy_func) (value_to_free);
    }

  return !already_exists;
}

void
gum_metal_hash_table_iter_replace (GumMetalHashTableIter *iter,
                           gpointer        value)
{
  RealIter *ri;
  guint node_hash;
  gpointer key;

  ri = (RealIter *) iter;

  g_return_if_fail (ri != NULL);
  g_return_if_fail (ri->position >= 0);
  g_return_if_fail (ri->position < ri->hash_table->size);

  node_hash = ri->hash_table->hashes[ri->position];
  key = ri->hash_table->keys[ri->position];

  gum_metal_hash_table_insert_node (ri->hash_table, ri->position, node_hash, key, value, TRUE, TRUE);
}

void
gum_metal_hash_table_iter_steal (GumMetalHashTableIter *iter)
{
  iter_remove_or_steal ((RealIter *) iter, FALSE);
}


GumMetalHashTable *
gum_metal_hash_table_ref (GumMetalHashTable *hash_table)
{
  g_return_val_if_fail (hash_table != NULL, NULL);

  g_atomic_int_inc (&hash_table->ref_count);

  return hash_table;
}

void
gum_metal_hash_table_unref (GumMetalHashTable *hash_table)
{
  g_return_if_fail (hash_table != NULL);

  if (g_atomic_int_dec_and_test (&hash_table->ref_count))
    {
      gum_metal_hash_table_remove_all_nodes (hash_table, TRUE);
      if (hash_table->keys != hash_table->values)
        gum_internal_free (hash_table->values);
      gum_internal_free (hash_table->keys);
      gum_internal_free (hash_table->hashes);
      gum_internal_free (hash_table);
    }
}

void
gum_metal_hash_table_destroy (GumMetalHashTable *hash_table)
{
  g_return_if_fail (hash_table != NULL);

  gum_metal_hash_table_remove_all (hash_table);
  gum_metal_hash_table_unref (hash_table);
}

gpointer
gum_metal_hash_table_lookup (GumMetalHashTable    *hash_table,
                     gconstpointer  key)
{
  guint node_index;
  guint node_hash;

  g_return_val_if_fail (hash_table != NULL, NULL);

  node_index = gum_metal_hash_table_lookup_node (hash_table, key, &node_hash);

  return HASH_IS_REAL (hash_table->hashes[node_index])
    ? hash_table->values[node_index]
    : NULL;
}

gboolean
gum_metal_hash_table_lookup_extended (GumMetalHashTable    *hash_table,
                              gconstpointer  lookup_key,
                              gpointer      *orig_key,
                              gpointer      *value)
{
  guint node_index;
  guint node_hash;

  g_return_val_if_fail (hash_table != NULL, FALSE);

  node_index = gum_metal_hash_table_lookup_node (hash_table, lookup_key, &node_hash);

  if (!HASH_IS_REAL (hash_table->hashes[node_index]))
    return FALSE;

  if (orig_key)
    *orig_key = hash_table->keys[node_index];

  if (value)
    *value = hash_table->values[node_index];

  return TRUE;
}

static gboolean
gum_metal_hash_table_insert_internal (GumMetalHashTable *hash_table,
                              gpointer    key,
                              gpointer    value,
                              gboolean    keep_new_key)
{
  guint key_hash;
  guint node_index;

  g_return_val_if_fail (hash_table != NULL, FALSE);

  node_index = gum_metal_hash_table_lookup_node (hash_table, key, &key_hash);

  return gum_metal_hash_table_insert_node (hash_table, node_index, key_hash, key, value, keep_new_key, FALSE);
}

gboolean
gum_metal_hash_table_insert (GumMetalHashTable *hash_table,
                     gpointer    key,
                     gpointer    value)
{
  return gum_metal_hash_table_insert_internal (hash_table, key, value, FALSE);
}

gboolean
gum_metal_hash_table_replace (GumMetalHashTable *hash_table,
                      gpointer    key,
                      gpointer    value)
{
  return gum_metal_hash_table_insert_internal (hash_table, key, value, TRUE);
}

gboolean
gum_metal_hash_table_add (GumMetalHashTable *hash_table,
                  gpointer    key)
{
  return gum_metal_hash_table_insert_internal (hash_table, key, key, TRUE);
}

gboolean
gum_metal_hash_table_contains (GumMetalHashTable    *hash_table,
                       gconstpointer  key)
{
  guint node_index;
  guint node_hash;

  g_return_val_if_fail (hash_table != NULL, FALSE);

  node_index = gum_metal_hash_table_lookup_node (hash_table, key, &node_hash);

  return HASH_IS_REAL (hash_table->hashes[node_index]);
}

static gboolean
gum_metal_hash_table_remove_internal (GumMetalHashTable    *hash_table,
                              gconstpointer  key,
                              gboolean       notify)
{
  guint node_index;
  guint node_hash;

  g_return_val_if_fail (hash_table != NULL, FALSE);

  node_index = gum_metal_hash_table_lookup_node (hash_table, key, &node_hash);

  if (!HASH_IS_REAL (hash_table->hashes[node_index]))
    return FALSE;

  gum_metal_hash_table_remove_node (hash_table, node_index, notify);
  gum_metal_hash_table_maybe_resize (hash_table);

  return TRUE;
}

gboolean
gum_metal_hash_table_remove (GumMetalHashTable    *hash_table,
                     gconstpointer  key)
{
  return gum_metal_hash_table_remove_internal (hash_table, key, TRUE);
}

gboolean
gum_metal_hash_table_steal (GumMetalHashTable    *hash_table,
                    gconstpointer  key)
{
  return gum_metal_hash_table_remove_internal (hash_table, key, FALSE);
}

void
gum_metal_hash_table_remove_all (GumMetalHashTable *hash_table)
{
  g_return_if_fail (hash_table != NULL);

  gum_metal_hash_table_remove_all_nodes (hash_table, TRUE);
  gum_metal_hash_table_maybe_resize (hash_table);
}

void
gum_metal_hash_table_steal_all (GumMetalHashTable *hash_table)
{
  g_return_if_fail (hash_table != NULL);

  gum_metal_hash_table_remove_all_nodes (hash_table, FALSE);
  gum_metal_hash_table_maybe_resize (hash_table);
}

static guint
gum_metal_hash_table_foreach_remove_or_steal (GumMetalHashTable *hash_table,
                                      GHRFunc     func,
                                      gpointer    user_data,
                                      gboolean    notify)
{
  guint deleted = 0;
  gint i;

  for (i = 0; i < hash_table->size; i++)
    {
      guint node_hash = hash_table->hashes[i];
      gpointer node_key = hash_table->keys[i];
      gpointer node_value = hash_table->values[i];

      if (HASH_IS_REAL (node_hash) &&
          (* func) (node_key, node_value, user_data))
        {
          gum_metal_hash_table_remove_node (hash_table, i, notify);
          deleted++;
        }
    }

  gum_metal_hash_table_maybe_resize (hash_table);

  return deleted;
}

guint
gum_metal_hash_table_foreach_remove (GumMetalHashTable *hash_table,
                             GHRFunc     func,
                             gpointer    user_data)
{
  g_return_val_if_fail (hash_table != NULL, 0);
  g_return_val_if_fail (func != NULL, 0);

  return gum_metal_hash_table_foreach_remove_or_steal (hash_table, func, user_data, TRUE);
}

guint
gum_metal_hash_table_foreach_steal (GumMetalHashTable *hash_table,
                            GHRFunc     func,
                            gpointer    user_data)
{
  g_return_val_if_fail (hash_table != NULL, 0);
  g_return_val_if_fail (func != NULL, 0);

  return gum_metal_hash_table_foreach_remove_or_steal (hash_table, func, user_data, FALSE);
}

void
gum_metal_hash_table_foreach (GumMetalHashTable *hash_table,
                      GHFunc      func,
                      gpointer    user_data)
{
  gint i;

  g_return_if_fail (hash_table != NULL);
  g_return_if_fail (func != NULL);

  for (i = 0; i < hash_table->size; i++)
    {
      guint node_hash = hash_table->hashes[i];
      gpointer node_key = hash_table->keys[i];
      gpointer node_value = hash_table->values[i];

      if (HASH_IS_REAL (node_hash))
        (* func) (node_key, node_value, user_data);
    }
}

gpointer
gum_metal_hash_table_find (GumMetalHashTable *hash_table,
                   GHRFunc     predicate,
                   gpointer    user_data)
{
  gint i;
  gboolean match;

  g_return_val_if_fail (hash_table != NULL, NULL);
  g_return_val_if_fail (predicate != NULL, NULL);

  match = FALSE;

  for (i = 0; i < hash_table->size; i++)
    {
      guint node_hash = hash_table->hashes[i];
      gpointer node_key = hash_table->keys[i];
      gpointer node_value = hash_table->values[i];

      if (HASH_IS_REAL (node_hash))
        match = predicate (node_key, node_value, user_data);

      if (match)
        return node_value;
    }

  return NULL;
}

guint
gum_metal_hash_table_size (GumMetalHashTable *hash_table)
{
  g_return_val_if_fail (hash_table != NULL, 0);

  return hash_table->nnodes;
}


"""

```