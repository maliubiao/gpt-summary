Response:
### 功能归纳

该文件 `plist.vala` 是 Frida 工具中用于处理 **Plist（Property List）** 文件的核心模块。Plist 是苹果公司开发的一种用于存储结构化数据的文件格式，常用于 macOS 和 iOS 系统中。该文件实现了对 Plist 文件的解析、生成和操作功能，支持二进制和 XML 两种格式。

#### 主要功能：
1. **Plist 文件解析**：
   - 支持从二进制格式（`bplist`）和 XML 格式的 Plist 文件中读取数据。
   - 提供了 `Plist.from_binary()` 和 `Plist.from_xml()` 方法，分别用于从二进制和 XML 格式的数据中解析 Plist 文件。
   - 解析后的数据存储在 `PlistDict` 或 `PlistArray` 中，支持嵌套的字典和数组结构。

2. **Plist 文件生成**：
   - 支持将 Plist 数据转换为二进制格式或 XML 格式。
   - 提供了 `Plist.to_binary()` 和 `Plist.to_xml()` 方法，分别用于生成二进制和 XML 格式的 Plist 文件。

3. **Plist 数据操作**：
   - 提供了 `PlistDict` 类，用于表示 Plist 中的字典结构，支持键值对的增删改查操作。
   - 提供了 `PlistArray` 类，用于表示 Plist 中的数组结构，支持元素的增删改查操作。
   - 支持多种数据类型，包括布尔值、整数、浮点数、字符串、二进制数据、日期等。

4. **错误处理**：
   - 提供了 `PlistError` 异常类，用于处理 Plist 文件解析和操作过程中可能出现的错误。

5. **底层二进制处理**：
   - 实现了对二进制 Plist 文件的底层解析和生成逻辑，包括对二进制数据的读取、写入、偏移量计算等操作。
   - 支持大端序（Big Endian）和小端序（Little Endian）的数据处理。

6. **XML 处理**：
   - 实现了对 XML 格式 Plist 文件的解析和生成逻辑，使用 `MarkupParser` 进行 XML 解析。

#### 涉及二进制底层和 Linux 内核的示例：
- **二进制数据处理**：在 `BinaryParser` 类中，使用了 `DataInputStream` 和 `MemoryInputStream` 来读取二进制数据，并通过 `seek()` 方法定位数据偏移量。例如：
  ```vala
  input.seek(-26, END);  // 从文件末尾向前移动 26 字节
  offset_size = input.read_byte();  // 读取偏移量大小
  ```
  这种操作类似于 Linux 内核中的文件 I/O 操作，例如使用 `lseek()` 和 `read()` 系统调用。

- **大端序处理**：在读取二进制数据时，使用了 `BIG_ENDIAN` 字节序，例如：
  ```vala
  input.byte_order = BIG_ENDIAN;
  ```
  这与 Linux 内核中的字节序处理类似，例如在读取网络数据包时，通常需要处理大端序数据。

#### 使用 LLDB 调试的示例：
假设我们想要调试 `Plist.from_binary()` 方法的执行过程，可以使用 LLDB 设置断点并查看变量值。

1. **设置断点**：
   ```bash
   lldb ./frida
   (lldb) b plist.vala:123  # 假设在 BinaryParser.parse() 方法的第 123 行设置断点
   (lldb) run
   ```

2. **查看变量**：
   当程序执行到断点时，可以使用 LLDB 查看变量的值：
   ```bash
   (lldb) p offset_size
   (lldb) p object_ref_size
   ```

3. **单步执行**：
   使用 `next` 命令单步执行代码：
   ```bash
   (lldb) next
   ```

4. **Python 脚本**：
   可以使用 LLDB 的 Python API 编写脚本来自动化调试过程：
   ```python
   import lldb

   def breakpoint_handler(frame, bp_loc, dict):
       print("Breakpoint hit at:", frame.GetLineEntry().GetFileSpec().GetFilename())
       print("Offset size:", frame.FindVariable("offset_size").GetValue())
       return False

   debugger = lldb.SBDebugger.Create()
   target = debugger.CreateTarget("frida")
   breakpoint = target.BreakpointCreateByLocation("plist.vala", 123)
   breakpoint.SetScriptCallbackFunction("breakpoint_handler")
   ```

#### 假设输入与输出：
- **输入**：一个二进制 Plist 文件 `example.bplist`，内容为一个包含键值对的字典。
- **输出**：解析后的 `PlistDict` 对象，可以通过 `get_string()` 等方法获取具体的值。

#### 常见使用错误：
1. **文件格式错误**：
   - 如果提供的二进制文件不是有效的 Plist 文件，解析时会抛出 `PlistError.INVALID_DATA` 异常。
   - 示例错误：`Invalid binary plist`。

2. **数据类型不匹配**：
   - 如果尝试从一个键中获取不匹配的数据类型（例如，尝试用 `get_string()` 获取一个整数），会抛出 `PlistError` 异常。
   - 示例错误：`Dict keys must be strings, not int64`。

3. **内存泄漏**：
   - 如果在操作 `PlistDict` 或 `PlistArray` 时没有正确释放内存，可能会导致内存泄漏。
   - 示例错误：未调用 `free_value()` 释放 `Value` 对象。

#### 用户操作路径：
1. 用户调用 `Plist.from_binary()` 或 `Plist.from_xml()` 方法，传入二进制或 XML 格式的 Plist 文件。
2. 解析器（`BinaryParser` 或 `XmlParser`）开始解析文件，生成 `PlistDict` 或 `PlistArray` 对象。
3. 用户通过 `PlistDict` 或 `PlistArray` 的方法操作数据，例如获取、设置或删除键值对。
4. 用户调用 `Plist.to_binary()` 或 `Plist.to_xml()` 方法，将数据转换为二进制或 XML 格式并保存。

#### 调试线索：
- 如果解析失败，可以检查输入文件的格式是否正确。
- 如果数据类型不匹配，可以检查代码中是否错误地使用了 `get_*()` 方法。
- 如果出现内存泄漏，可以检查是否在所有 `Value` 对象使用完毕后调用了 `free_value()`。

这是第 1 部分的功能归纳，第 2 部分将继续分析剩余代码的功能。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/plist.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public class Plist : PlistDict {
		public enum Format {
			AUTO,
			BINARY,
			XML
		}

		private const int64 MAC_EPOCH_DELTA_FROM_UNIX = 978307200LL;

		public Plist.from_binary (uint8[] data) throws PlistError {
			this.from_data (data, BINARY);
		}

		public Plist.from_xml (string xml) throws PlistError {
			this.from_data (xml.data, XML);
		}

		public Plist.from_data (uint8[] data, Format format = AUTO) throws PlistError {
			if (format == AUTO) {
				unowned string magic = (string) data;
				if (magic.has_prefix ("bplist")) {
					format = BINARY;
				} else {
					format = XML;
				}
			}
			if (format == BINARY) {
				var parser = new BinaryParser (this);
				parser.parse (data);
			} else if (format == XML) {
				var parser = new XmlParser (this);
				parser.parse ((string) data);
			} else {
				assert_not_reached ();
			}
		}

		public uint8[] to_binary () {
			var output = new MemoryOutputStream.resizable ();

			var writer = new BinaryWriter (output);
			try {
				writer.write_plist (this);

				output.close ();

				uint8[] data = output.steal_data ();
				data.length = (int) output.data_size;
				return data;
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		public string to_xml () {
			var builder = new StringBuilder ();
			var writer = new XmlWriter (builder);
			writer.write_plist (this);
			return builder.str;
		}

		private class BinaryParser : Object {
			public Plist plist {
				get;
				construct;
			}

			private DataInputStream input;

			private uint8 offset_size;
			private uint8 object_ref_size;
			private uint64 offset_table_offset;

			private uint8 object_info;

			private const uint64 MAX_OBJECT_SIZE = 100 * 1024 * 1024;
			private const uint64 MAX_OBJECT_COUNT = 32 * 1024;

			public BinaryParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (uint8[] data) throws PlistError {
				unowned string magic = (string) data;
				if (!magic.has_prefix ("bplist"))
					throw new PlistError.INVALID_DATA ("Invalid binary plist");

				try {
					input = new DataInputStream (new MemoryInputStream.from_bytes (new Bytes.static (data)));
					input.byte_order = BIG_ENDIAN;

					input.seek (-26, END);
					offset_size = input.read_byte ();
					object_ref_size = input.read_byte ();
					var num_objects = input.read_uint64 ();
					if (num_objects > MAX_OBJECT_COUNT)
						throw new PlistError.INVALID_DATA ("Too many objects");
					var top_object_ref = input.read_uint64 ();
					offset_table_offset = input.read_uint64 ();

					var top_object = parse_object (top_object_ref);
					if (!top_object.holds (typeof (PlistDict)))
						throw new PlistError.INVALID_DATA ("Toplevel must be a dict");
					plist.steal_all ((PlistDict) top_object.get_object ());
				} catch (GLib.Error e) {
					throw new PlistError.INVALID_DATA ("Invalid binary plist: %s", e.message);
				}
			}

			private Value? parse_object (uint64 object_ref) throws GLib.Error {
				Value? obj;

				var previous_offset = input.tell ();
				try {
					seek_to_object (object_ref);

					obj = read_value ();
				} catch (GLib.Error e) {
					input.seek (previous_offset, SET);
					throw e;
				}

				input.seek (previous_offset, SET);

				return obj;
			}

			private void seek_to_object (uint64 object_ref) throws GLib.Error {
				input.seek ((int64) (offset_table_offset + (object_ref * offset_size)), SET);
				var offset = read_offset ();
				input.seek ((int64) offset, SET);
			}

			private Value? read_value () throws GLib.Error {
				uint8 marker = input.read_byte ();
				uint8 object_type = (marker & 0xf0) >> 4;
				object_info = marker & 0x0f;

				switch (object_type) {
					case 0x0:
						return read_constant ();
					case 0x1:
						return read_integer ();
					case 0x2:
						return read_real ();
					case 0x3:
						return read_date ();
					case 0x4:
						return read_data ();
					case 0x5:
						return read_ascii_string ();
					case 0x6:
						return read_utf16_string ();
					case 0x8:
						return read_uid ();
					case 0xa:
						return read_array ();
					case 0xd:
						return read_dict ();
					default:
						throw new PlistError.INVALID_DATA ("Unsupported object type: 0x%x", object_type);
				}
			}

			private Value? read_constant () throws GLib.Error {
				Value? gval;

				switch (object_info) {
					case 0x0:
						gval = Value (typeof (PlistNull));
						gval.take_object (new PlistNull ());
						break;
					case 0x8:
					case 0x9:
						gval = Value (typeof (bool));
						gval.set_boolean (object_info == 0x9);
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported constant type: 0x%x", object_info);
				}

				return gval;
			}

			private Value? read_integer () throws GLib.Error {
				if (object_info > 4)
					throw new PlistError.INVALID_DATA ("Integer too large");
				uint size = 1 << object_info;

				int64 val;
				switch (size) {
					case 1:
						val = input.read_byte ();
						break;
					case 2:
						val = input.read_uint16 ();
						break;
					case 4:
						val = input.read_uint32 ();
						break;
					case 8:
						val = input.read_int64 ();
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported integer size: %u", size);
				}

				var gval = Value (typeof (int64));
				gval.set_int64 (val);
				return gval;
			}

			private Value? read_real () throws GLib.Error {
				Value? gval;

				switch (object_info) {
					case 2:
						gval = Value (typeof (float));
						gval.set_float (read_float ());
						break;
					case 3:
						gval = Value (typeof (double));
						gval.set_double (read_double ());
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported number size: %u", 1 << object_info);
				}

				return gval;
			}

			private float read_float () throws GLib.Error {
				uint32 bits = input.read_uint32 ();
				float * val = (float *) &bits;
				return *val;
			}

			private double read_double () throws GLib.Error {
				uint64 bits = input.read_uint64 ();
				double * val = (double *) &bits;
				return *val;
			}

			private Value? read_date () throws GLib.Error {
				double point_in_time = read_double ();
				int64 whole_seconds = (int64) point_in_time;
				var val = new DateTime.from_unix_utc (MAC_EPOCH_DELTA_FROM_UNIX + whole_seconds)
					.add_seconds (point_in_time - (double) whole_seconds);

				var gval = Value (typeof (PlistDate));
				gval.take_object (new PlistDate (val));
				return gval;
			}

			private Value? read_data () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length);

				var buf = new uint8[length];
				size_t bytes_read;
				input.read_all (buf, out bytes_read);

				var gval = Value (typeof (Bytes));
				gval.take_boxed (new Bytes.take ((owned) buf));
				return gval;
			}

			private Value? read_ascii_string () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length);

				var str_buf = new uint8[length + 1];
				str_buf[length] = 0;
				size_t bytes_read;
				input.read_all (str_buf[0:length], out bytes_read);

				unowned string str = (string) str_buf;

				var gval = Value (typeof (string));
				gval.set_string (str);
				return gval;
			}

			private Value? read_utf16_string () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				uint64 size = length * sizeof (uint16);
				check_object_size (size);

				var str_chars = new uint16[length + 1];
				str_chars[length] = 0;
				unowned uint8[] str_buf = (uint8[]) str_chars;
				size_t bytes_read;
				input.read_all (str_buf[0:size], out bytes_read);

				for (uint64 i = 0; i != length; i++)
					str_chars[i] = uint16.from_big_endian (str_chars[i]);

				unowned string16 str = (string16) str_chars;

				var gval = Value (typeof (string));
				gval.set_string (str.to_utf8 ());
				return gval;
			}

			private Value? read_uid () throws GLib.Error {
				uint64 val = read_uint_of_size (object_info + 1);

				var gval = Value (typeof (PlistUid));
				gval.take_object (new PlistUid (val));
				return gval;
			}

			private Value? read_array () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length * object_ref_size);

				var element_refs = new uint64[length];
				for (uint64 i = 0; i != length; i++)
					element_refs[i] = read_ref ();

				var array = new PlistArray ();

				for (uint64 i = 0; i != length; i++) {
					var element = parse_object (element_refs[i]);
					array.add_value (element);
				}

				var gval = Value (typeof (PlistArray));
				gval.set_object (array);
				return gval;
			}

			private Value? read_dict () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length * (2 * object_ref_size));

				var key_refs = new uint64[length];
				var val_refs = new uint64[length];
				for (uint64 i = 0; i != length; i++)
					key_refs[i] = read_ref ();
				for (uint64 i = 0; i != length; i++)
					val_refs[i] = read_ref ();

				var dict = new PlistDict ();

				for (uint64 i = 0; i != length; i++) {
					var key = parse_object (key_refs[i]);
					var val = parse_object (val_refs[i]);

					if (!key.holds (typeof (string)))
						throw new PlistError.INVALID_DATA ("Dict keys must be strings, not %s", key.type_name ());

					dict.set_value (key.get_string (), (owned) val);
				}

				var gval = Value (typeof (PlistDict));
				gval.set_object (dict);
				return gval;
			}

			private uint64 read_offset () throws GLib.Error {
				return read_uint_of_size (offset_size);
			}

			private uint64 read_ref () throws GLib.Error {
				return read_uint_of_size (object_ref_size);
			}

			private uint64 read_length () throws GLib.Error {
				var val = read_value ();
				if (!val.holds (typeof (int64)))
					throw new PlistError.INVALID_DATA ("Length must be an integer");

				int64 length = val.get_int64 ();
				if (length < 0)
					throw new PlistError.INVALID_DATA ("Length must be positive");

				return length;
			}

			private uint64 read_uint_of_size (uint size) throws GLib.Error {
				switch (size) {
					case 1:
						return input.read_byte ();
					case 2:
						return input.read_uint16 ();
					case 4:
						return input.read_uint32 ();
					case 8:
						return input.read_uint64 ();
					default:
						throw new PlistError.INVALID_DATA ("Unsupported uint size: %u", size);
				}
			}

			private void check_object_size (uint64 size) throws PlistError {
				if (size > MAX_OBJECT_SIZE)
					throw new PlistError.INVALID_DATA ("Object too large");
			}
		}

		private class BinaryWriter {
			private DataOutputStream output;
			private Seekable seekable;

			private Gee.ArrayList<Value *> temporary_values = new Gee.ArrayList<Value *> ();
			private uint next_id = 0;

			private uint8 offset_size;
			private uint8 object_ref_size;

			public BinaryWriter (OutputStream stream) {
				output = new DataOutputStream (stream);
				output.byte_order = BIG_ENDIAN;
				seekable = (Seekable) output;
			}

			private void reset () {
				next_id = 0;

				temporary_values.foreach (free_value);
				temporary_values.clear ();
			}

			public void write_plist (Plist plist) throws IOError {
				try {
					output.put_string ("bplist00");

					var unique_entries = new Gee.HashMap<Value *, Entry> (hash_value, compare_values_eq);
					var root = make_value (typeof (PlistDict));
					root.set_object (plist);
					temporary_values.add (root);
					var root_entry = collect_value (root, unique_entries);
					uint num_objects = unique_entries.size;
					object_ref_size = compute_object_ref_size (num_objects);

					var sorted_entries = new Gee.ArrayList<Entry> ();
					sorted_entries.add_all (unique_entries.values);
					sorted_entries.sort ((a, b) => (int) a.id - (int) b.id);

					foreach (var entry in sorted_entries)
						write_entry (entry);

					size_t offset_table_offset = (size_t) seekable.tell ();
					offset_size = compute_offset_size (sorted_entries.last ().offset);
					foreach (var entry in sorted_entries)
						write_offset (entry.offset);

					const uint trailer_null_pad_size = 6;
					for (uint i = 0; i != trailer_null_pad_size; i++)
						output.put_byte (0x00);
					output.put_byte (offset_size);
					output.put_byte (object_ref_size);
					output.put_uint64 (num_objects);
					output.put_uint64 (root_entry.id);
					output.put_uint64 (offset_table_offset);
				} finally {
					reset ();
				}
			}

			private Entry collect_value (Value * v, Gee.HashMap<Value *, Entry> unique_entries) {
				bool is_dict = v.holds (typeof (PlistDict));
				bool is_array = v.holds (typeof (PlistArray));

				Entry? entry = unique_entries[v];
				if (entry == null) {
					uint id = next_id++;
					if (is_dict)
						entry = new DictEntry (id, v);
					else if (is_array)
						entry = new ArrayEntry (id, v);
					else
						entry = new Entry (id, v);
					unique_entries[v] = entry;
				}

				if (is_dict) {
					var dict = (PlistDict) v.get_object ();
					DictEntry dict_entry = (DictEntry) entry;

					var values = new Gee.ArrayList<Value *> ();

					foreach (var e in dict.entries) {
						var k = make_value (typeof (string));
						k.set_string (e.key);
						Entry? key_entry = unique_entries[k];
						if (key_entry == null) {
							key_entry = new Entry (next_id++, k);
							unique_entries[k] = key_entry;
							temporary_values.add (k);
						} else {
							free_value (k);
						}
						dict_entry.keys.add (key_entry);

						values.add (e.value);
					}

					foreach (var val in values) {
						var val_entry = collect_value (val, unique_entries);
						dict_entry.values.add (val_entry);
					}

					return entry;
				}

				if (is_array) {
					var array = (PlistArray) v.get_object ();
					ArrayEntry array_entry = (ArrayEntry) entry;

					foreach (var val in array.elements) {
						var element_entry = collect_value (val, unique_entries);
						array_entry.elements.add (element_entry);
					}

					return entry;
				}

				return entry;
			}

			private void write_entry (Entry entry) throws IOError {
				entry.offset = seekable.tell ();

				Value * val = entry.val;
				Type t = val.type ();

				if (t == typeof (PlistNull)) {
					write_null ();
					return;
				}

				if (t == typeof (bool)) {
					write_boolean (val.get_boolean ());
					return;
				}

				if (t == typeof (int64)) {
					write_integer (val.get_int64 ());
					return;
				}

				if (t == typeof (float)) {
					write_float (val.get_float ());
					return;
				}

				if (t == typeof (double)) {
					write_double (val.get_double ());
					return;
				}

				if (t == typeof (PlistDate)) {
					write_date ((PlistDate) val.get_object ());
					return;
				}

				if (t == typeof (Bytes)) {
					write_data ((Bytes) val.get_boxed ());
					return;
				}

				if (t == typeof (string)) {
					write_string (val.get_string ());
					return;
				}

				if (t == typeof (PlistUid)) {
					write_uid ((PlistUid) val.get_object ());
					return;
				}

				if (t == typeof (PlistArray)) {
					write_array ((PlistArray) val.get_object (), (ArrayEntry) entry);
					return;
				}

				if (t == typeof (PlistDict)) {
					write_dict ((PlistDict) val.get_object (), (DictEntry) entry);
					return;
				}

				assert_not_reached ();
			}

			private void write_null () throws IOError {
				output.put_byte (0x00);
			}

			private void write_boolean (bool val) throws IOError {
				output.put_byte (0x08 | (val ? 0x01 : 0x00));
			}

			private void write_integer (int64 val) throws IOError {
				if (val >= 0 && val <= uint8.MAX) {
					output.put_byte (0x10);
					output.put_byte ((uint8) val);
					return;
				}

				if (val >= 0 && val <= uint16.MAX) {
					output.put_byte (0x11);
					output.put_uint16 ((uint16) val);
					return;
				}

				if (val >= 0 && val <= uint32.MAX) {
					output.put_byte (0x12);
					output.put_uint32 ((uint32) val);
					return;
				}

				if (val < 0) {
					output.put_byte (0x13);
					output.put_int64 (val);
					return;
				}

				output.put_byte (0x14);
				output.put_uint64 (val);
			}

			private void write_float (float val) throws IOError {
				output.put_byte (0x22);

				uint32 bits = *((uint32 *) &val);
				output.put_uint32 (bits);
			}

			private void write_double (double val) throws IOError {
				output.put_byte (0x23);

				uint64 bits = *((uint64 *) &val);
				output.put_uint64 (bits);
			}

			private void write_date (PlistDate date) throws IOError {
				output.put_byte (0x33);

				var val = date.get_time ();
				double point_in_time = (double) (val.to_unix () - MAC_EPOCH_DELTA_FROM_UNIX) + val.get_seconds ();
				uint64 bits = *((uint64 *) &point_in_time);
				output.put_uint64 (bits);
			}

			private void write_data (Bytes bytes) throws IOError {
				var data = bytes.get_data ();

				write_size_header (0x4, data.length);

				size_t bytes_written;
				output.write_all (data, out bytes_written);
			}

			private void write_string (string str) throws IOError {
				int native_size = str.length;
				if (str.char_count () == native_size) {
					write_size_header (0x5, native_size);

					output.put_string (str);
				} else {
					long num_chars;
					string16 utf16_str;
					try {
						utf16_str = str.to_utf16 (-1, null, out num_chars);
					} catch (ConvertError e) {
						assert_not_reached ();
					}
					unowned uint16[] chars = ((uint16[]) utf16_str)[0:num_chars];
					for (long i = 0; i != num_chars; i++)
						chars[i] = chars[i].to_big_endian ();

					write_size_header (0x6, num_chars);

					size_t size = num_chars * sizeof (uint16);
					unowned uint8[] data = ((uint8[]) chars)[0:size];
					size_t bytes_written;
					output.write_all (data, out bytes_written);
				}
			}

			private void write_uid (PlistUid val) throws IOError {
				output.put_byte (0x80 | (object_ref_size - 1));

				write_ref ((uint) val.uid);
			}

			private void write_array (PlistArray array, ArrayEntry array_entry) throws IOError {
				write_size_header (0xa, array.length);

				foreach (var entry in array_entry.elements)
					write_ref (entry.id);
			}

			private void write_dict (PlistDict dict, DictEntry dict_entry) throws IOError {
				write_size_header (0xd, dict.size);

				foreach (var entry in dict_entry.keys)
					write_ref (entry.id);

				foreach (var entry in dict_entry.values)
					write_ref (entry.id);
			}

			private void write_size_header (uint8 object_type, size_t size) throws IOError {
				if (size < 15) {
					output.put_byte ((object_type << 4) | (uint8) size);
					return;
				}

				output.put_byte ((object_type << 4) | 0x0f);

				if (size <= uint8.MAX) {
					output.put_byte (0x10);
					output.put_byte ((uint8) size);
					return;
				}

				if (size <= uint16.MAX) {
					output.put_byte (0x11);
					output.put_uint16 ((uint16) size);
					return;
				}

				if (size <= uint32.MAX) {
					output.put_byte (0x12);
					output.put_uint32 ((uint32) size);
					return;
				}

				assert_not_reached ();
			}

			private void write_offset (uint64 offset) throws IOError {
				switch (offset_size) {
					case 1:
						output.put_byte ((uint8) offset);
						break;
					case 2:
						output.put_uint16 ((uint16) offset);
						break;
					case 4:
						output.put_uint32 ((uint32) offset);
						break;
					case 8:
						output.put_uint64 (offset);
						break;
					default:
						assert_not_reached ();
				}
			}

			private void write_ref (uint id) throws IOError {
				switch (object_ref_size) {
					case 1:
						output.put_byte ((uint8) id);
						break;
					case 2:
						output.put_uint16 ((uint16) id);
						break;
					case 4:
						output.put_uint32 (id);
						break;
					default:
						assert_not_reached ();
				}
			}

			private static uint8 compute_offset_size (uint64 largest_offset) {
				if (largest_offset <= uint8.MAX)
					return (uint8) sizeof (uint8);

				if (largest_offset <= uint16.MAX)
					return (uint8) sizeof (uint16);

				if (largest_offset <= uint32.MAX)
					return (uint8) sizeof (uint32);

				return (uint8) sizeof (uint64);
			}

			private static uint8 compute_object_ref_size (uint num_ids) {
				if (num_ids <= uint8.MAX)
					return (uint8) sizeof (uint8);

				if (num_ids <= uint16.MAX)
					return (uint8) sizeof (uint16);

				return (uint8) sizeof (uint32);
			}

			private class Entry {
				public uint id;
				public uint64 offset;
				public Value * val;

				public Entry (uint id, Value * val) {
					this.id = id;
					this.val = val;
				}
			}

			private class DictEntry : Entry {
				public Gee.ArrayList<Entry> keys = new Gee.ArrayList<Entry> ();
				public Gee.ArrayList<Entry> values = new Gee.ArrayList<Entry> ();

				public DictEntry (uint id, Value * val) {
					base (id, val);
				}
			}

			private class ArrayEntry : Entry {
				public Gee.ArrayList<Entry> elements = new Gee.ArrayList<Entry> ();

				public ArrayEntry (uint id, Value * val) {
					base (id, val);
				}
			}
		}

		private class XmlParser : Object {
			public Plist plist {
				get;
				construct;
			}

			private const MarkupParser parser = {
				on_start_element,
				on_end_element,
				on_text,
				null,
				null
			};

			private Gee.Deque<PartialValue> stack = new Gee.LinkedList<PartialValue> ();

			public XmlParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (string xml) throws PlistError {
				try {
					var context = new MarkupParseContext (parser, 0, this, null);
					context.parse (xml, -1);
				} catch (MarkupError e) {
					throw new PlistError.INVALID_DATA ("%s", e.message);
				}
			}

			private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names, string[] attribute_values) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null) {
					if (element_name == "dict")
						stack.offer_head (new PartialValue.with_dict (plist));
					return;
				}

				switch (partial.need) {
					case DICT_KEY_START:
						if (element_name == "key")
							partial.need = DICT_KEY_TEXT;
						break;
					case DICT_VALUE_START:
						partial.type = element_name;
						partial.val = null;

						if (element_name == "dict") {
							stack.offer_head (new PartialValue.with_dict (new PlistDict ()));
							partial.need = DICT_VALUE_END;
							return;
						}

						if (element_name == "array") {
							stack.offer_head (new PartialValue.with_array (new PlistArray ()));
							partial.need = DICT_VALUE_END;
							return;
						}

						partial.need = DICT_VALUE_TEXT_OR_END;

						break;
					case ARRAY_VALUE_START:
						partial.type = element_name;
						partial.val = null;

						if (element_name == "dict") {
							stack.offer_head (new PartialValue.with_dict (new PlistDict ()));
							partial.need = ARRAY_VALUE_END;
							return;
						}

						if (element_name == "array") {
							stack.offer_head (new PartialValue.with_array (new PlistArray ()));
							partial.need = ARRAY_VALUE_END;
							return;
						}

						partial.need = ARRAY_VALUE_TEXT_OR_END;

						break;
					default:
						break;
				}
			}

			private void on_end_element (MarkupParseContext context, string element_name) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null)
					return;

				switch (partial.need) {
					case DICT_KEY_START:
						if (element_name == "dict") {
							stack.poll_head ();

							var parent = stack.peek_head ();
							if (parent == null)
								return;

							switch (parent.need) {
								case DICT_VALUE_END:
									parent.dict.set_dict (parent.key, partial.dict);
									parent.need = DICT_KEY_START;
									break;
								case ARRAY_VALUE_END:
									parent.array.add_value (partial.dict);
									parent.need = ARRAY_VALUE_START;
									break;
								default:
									break;
							}
						}
						break;
					case ARRAY_VALUE_START:
						if (element_name == "array") {
							stack.poll_head ();

							var parent = stack.peek_head ();
							if (parent == null)
								return;

							switch (parent.need) {
								case DICT_VALUE_END:
									parent.dict.set_array (parent.key, partial.array);
									parent.need = DICT_KEY_START;
									break;
								case ARRAY_VALUE_END:
									parent.array.add_value (partial.array);
									parent.need = ARRAY_VALUE_START;
									break;
								default:
									break;
							}
						}
						break;
					case DICT_KEY_END:
						if (element_name == "key")
							partial.need = DICT_VALUE_START;
						break;
					case DICT_VALUE_TEXT_OR_END:
					case DICT_VALUE_END: {
						var val = try_create_value (partial.type, partial.val);
						if (val != null)
							partial.dict.set_value (partial.key, (owned) val);
						partial.need = DICT_KEY_START;
						break;
					}
					case ARRAY_VALUE_TEXT_OR_END:
					case ARRAY_VALUE_END: {
						var val = try_create_value (partial.type, partial.val);
						if (val != null)
							partial.array.add_value (val);
						partial.need = ARRAY_VALUE_START;
						break;
					}
					default:
						break;
				}
			}

			private void on_text (MarkupParseContext context, string text, size_t text_len) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null)
					return;

				switch (partial.need) {
					case DICT_KEY_TEXT:
						partial.key = text;
						partial.need = DICT_KEY_END;
						break;
					case DICT_VALUE_TEXT_OR_END:
						partial.val = text;
						partial.need = DICT_VALUE_END;
						break;
					case ARRAY_VALUE_TEXT_OR_END:
						partial.val = text;
						partial.need = ARRAY_VALUE_END;
						break;
					default:
						break;
				}
			}

			private class PartialValue {
				public enum Need {
					DICT_KEY_START,
					DICT_KEY_TEXT,
					DICT_KEY_END,
					DICT_VALUE_START,
					DICT_VALUE_TEXT_OR_END,
					DICT_VALUE_END,
					ARRAY_VALUE_START,
					ARRAY_VALUE_TEXT_OR_END,
					ARRAY_VALUE_END
				}

				public PlistDict? dict;
				public PlistArray? array;
				public Need need;
				public string? key;
				public string? type;
				public string? val;

				public PartialValue.with_dict (PlistDict dict) {
					this.dict = dict;
					this.need = DICT_KEY_START;
				}

				public PartialValue.with_array (PlistArray array) {
					this.array = array;
					this.need = ARRAY_VALUE_START;
				}
			}

			public Value? try_create_value (string? type, string? val) {
				Value? result = null;

				if (type == "true") {
					result = Value (typeof (bool));
					result.set_boolean (true);
				} else if (type == "false") {
					result = Value (typeof (bool));
					result.set_boolean (false);
				} else if (type == "integer") {
					result = Value (typeof (int64));
					result.set_int64 (int64.parse (val));
				} else if (type == "string") {
					result = Value (typeof (string));
					result.set_string (val);
				} else if (type == "data") {
					result = Value (typeof (Bytes));
					result.take_boxed (new Bytes.take (Base64.decode (val)));
				}

				return result;
			}
		}

		private class XmlWriter {
			private unowned StringBuilder builder;
			private uint level = 0;

			public XmlWriter (StringBuilder builder) {
				this.builder = builder;
			}

			public void write_plist (Plist plist) {
				write_line ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
				write_line ("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
				write_line ("<plist version=\"1.0\">");

				write_dict (plist);

				write_line ("</plist>");
			}

			public void write_dict (PlistDict dict) {
				write_line ("<dict>");
				level++;

				var keys = new Gee.ArrayList<string> ();
				foreach (var key in dict.keys)
					keys.add (key);
				keys.sort ();

				foreach (var key in keys) {
					write_tag ("key", key);

					Value * val;
					try {
						val = dict.get_value (key);
					} catch (PlistError e) {
						assert_not_reached ();
					}

					write_value (val);
				}

				level--;
				write_line ("</dict>");
			}

			public void write_array (PlistArray array) {
				write_line ("<array>");
				level++;

				foreach (var val in array.elements)
					write_value (val);

				level--;
				write_line ("</array>");
			}

			public void write_uid (PlistUid val) {
				write_line ("<dict>");
				level++;

				write_tag ("key", "CF$UID");
				write_tag ("integer", val.uid.to_string ());

				level--;
				write_line ("</dict>");
			}

			public void write_value (Value * val) {
				var type = val.type ();
				if (type == typeof (bool)) {
					write_tag (val.get_boolean ().to_string ());
				} else if (type == typeof (int64)) {
					write_tag ("integer", val.get_int64 ().to_string ());
				} else if (type == typeof (string)) {
					write_tag ("string", Markup.escape_text (val.get_string ()));
				} else if (type == typeof (Bytes)) {
					unowned Bytes bytes = (Bytes) val.get_boxed ();
					write_tag ("data", Base64.encode (bytes.get_data ()));
				} else if (type == typeof (PlistDict)) {
					write_dict ((PlistDict) val.get_object ());
				} else if (type == typeof (PlistArray)) {
					write_array ((PlistArray) val.get_object ());
				} else if (type == typeof (PlistUid)) {
					write_uid ((PlistUid) val.get_object ());
				}
			}

			private void write_tag (string name, string? content = null) {
				if (content != null)
					write_line ("<" + name + ">" + content + "</" + name + ">");
				else
					write_line ("<" + name + "/>");
			}

			private void write_line (string line) {
				for (uint i = 0; i != level; i++)
					builder.append_c ('\t');
				builder.append (line);
				builder.append ("\n");
			}
		}
	}

	public class PlistDict : Object {
		public bool is_empty {
			get {
				return storage.is_empty;
			}
		}

		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Set<Gee.Map.Entry<string, Value *>> entries {
			owned get {
				return storage.entries;
			}
		}

		public Gee.Iterable<string> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<Value *> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<string, Value *> storage = new Gee.HashMap<string, Value *> ();

		~PlistDict () {
			storage.values.foreach (free_value);
		}

		public PlistDict clone () {
			var result = new PlistDict ();
			foreach (var e in storage.entries)
				result.set_raw_value (e.key, clone_value (e.value));
			return result;
		}

		public void clear () {
			storage.values.foreach (free_value);
			storage.clear ();
		}

		public void remove (string key) {
			Value * v;
			if (storage.unset (key, out v))
				free_value (v);
		}

		public bool has (string key) {
			return storage.has_key (key);
		}

		public bool get_boolean (string key) throws PlistError {
			return get_value (key, typeof (bool)).get_boolean ();
		}

		public void set_boolean (string key, bool val) {
			var gval = make_value (typeof (bool));
			gval.set_boolean (val);
			set_raw_value (key, gval);
		}

		public int64 get_integer (string key) throws PlistError {
			return get_value (key, typeof (int64)).get_int64 ();
		}

		public void set_integer (string key, int64 val) {
			var gval = make_value (typeof (int64));
			gval.set_int64 (val);
			set_raw_value (key, gval);
		}

		public float get_float (string key) throws PlistError {
			return get_value (key, typeof (float)).get_float ();
		}

		public void set_float (string key, float val) {
			var gval = make_value (typeof (float));
			gval.set_float (val);
			set_raw_value (key, gval);
		}

		public double get_double (string key) throws PlistError {
			return get_value (key, typeof (double)).get_double ();
		}

		public void set_double (string key, double val) {
			var gval = make_value (typeof (double));
			gval.set_double (val);
			set_raw_value (key, gval);
		}

		public unowned string get_string (string key) throws PlistError {
			return get_value (key, typeof (string)).get_string ();
		}

		public void set_string (string key, string str) {
			var gval = make_value (typeof (string));
			gval.set_string (str);
			set_raw_value (key, gval);
		}

		public unowned Bytes get_bytes (string key) throws PlistError {
			return (Bytes) get_value (key, typeof (Bytes)).get_boxed ();
		}

		public string get_bytes_as_string (string key) throws PlistError {
			var bytes = get_bytes (key);
			unowned string unterminated_str = (string) bytes.get_data ();
			return unterminated_str[0:bytes.length];
		}

		public void set_bytes (string key, Bytes val) {
			var gval = make_value (typeof (Bytes));
			gval.set_boxed (val);
			set_raw_value (key, gval);
		}

		publ
"""


```