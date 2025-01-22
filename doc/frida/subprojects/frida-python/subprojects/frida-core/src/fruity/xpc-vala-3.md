Response:
### 功能归纳

该文件是Frida工具中用于处理XPC（跨进程通信）消息的核心模块，主要功能包括：

1. **XPC消息的构建与解析**：
   - `XpcMessageBuilder` 类用于构建XPC消息，支持添加消息类型、标志、ID和消息体。
   - `XpcMessage` 类用于解析XPC消息，支持从二进制数据中解析出消息类型、标志、ID和消息体。

2. **XPC消息的传输与处理**：
   - 通过 `SubmitOperation` 类处理消息的提交操作，支持消息的异步提交、错误处理和回调机制。
   - `on_data_frame_recv_chunk` 和 `on_data_frame_recv_end` 方法用于接收和处理XPC消息的帧数据。

3. **XPC消息体的构建与解析**：
   - `XpcBodyBuilder` 类用于构建XPC消息体，支持字典、数组、布尔值、整数、字符串、UUID等数据类型的构建。
   - `XpcBodyParser` 类用于解析XPC消息体，支持从二进制数据中解析出各种数据类型。

4. **密钥生成与UUID生成**：
   - `make_keypair` 函数用于生成密钥对。
   - `make_host_identifier` 函数用于生成主机标识符。
   - `make_random_v4_uuid` 函数用于生成随机的UUID。

### 二进制底层与Linux内核相关

- **密钥生成**：`make_keypair` 函数使用了底层的密钥生成机制，可能涉及到Linux内核的加密API或OpenSSL库。
- **UUID生成**：`make_random_v4_uuid` 函数使用了OpenSSL的随机数生成器（RNG）来生成随机的UUID。

### LLDB调试示例

假设我们想要调试 `XpcMessageBuilder` 类的 `build` 方法，可以使用以下LLDB命令或Python脚本：

#### LLDB命令

```lldb
b XpcMessageBuilder::build
run
p builder
```

#### LLDB Python脚本

```python
import lldb

def build_message(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 设置断点
    breakpoint = target.BreakpointCreateByName("XpcMessageBuilder::build")
    process.Continue()

    # 获取builder对象
    builder = frame.FindVariable("builder")
    print(builder)

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_script.build_message build_message')
```

### 假设输入与输出

假设我们构建一个XPC消息，输入如下：

```vala
var builder = new XpcMessageBuilder(MessageType.MSG)
    .add_flags(MessageFlags.WANTS_REPLY)
    .add_id(12345)
    .add_body(new Bytes.take("Hello, World!".data));
var message = builder.build();
```

输出将是一个包含消息类型、标志、ID和消息体的二进制数据。

### 常见使用错误

1. **消息体过大**：如果消息体超过 `MAX_SIZE`，会抛出 `Error.INVALID_ARGUMENT` 异常。
   - 示例：`builder.add_body(new Bytes.take(new uint8[128 * 1024 * 1024]));`

2. **消息类型不支持**：如果消息类型不在 `MessageType` 枚举中，会抛出 `Error.INVALID_ARGUMENT` 异常。
   - 示例：`var builder = new XpcMessageBuilder((MessageType) 99);`

### 用户操作路径

1. **构建XPC消息**：用户通过 `XpcMessageBuilder` 类构建XPC消息，设置消息类型、标志、ID和消息体。
2. **提交消息**：用户通过 `SubmitOperation` 类提交消息，处理异步提交和回调。
3. **接收与处理消息**：用户通过 `on_data_frame_recv_chunk` 和 `on_data_frame_recv_end` 方法接收和处理XPC消息的帧数据。
4. **解析消息体**：用户通过 `XpcBodyParser` 类解析XPC消息体，获取消息内容。

### 总结

该文件实现了Frida工具中XPC消息的构建、传输、接收和解析功能，支持多种数据类型的处理，并提供了密钥生成和UUID生成的工具函数。通过LLDB调试工具，可以方便地调试这些功能的实现。
Prompt: 
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/xpc.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第4部分，共4部分，请归纳一下它的功能

"""


				cancellable.set_error_if_cancelled ();

				if (op.state == ERROR)
					throw new Error.TRANSPORT ("%s", NGHttp2.strerror (op.error_code));
			}

			private void maybe_submit_data () {
				if (current_submission != null)
					return;

				SubmitOperation? op = submissions.peek_head ();
				if (op == null)
					return;
				current_submission = op;

				var data_prd = NGHttp2.DataProvider ();
				data_prd.source.ptr = op;
				data_prd.read_callback = on_data_provider_read;
				int result = parent.session.submit_data (NGHttp2.DataFlag.NO_END_STREAM, id, data_prd);
				if (result < 0) {
					while (true) {
						op = submissions.poll_head ();
						if (op == null)
							break;
						op.state = ERROR;
						op.error_code = (NGHttp2.ErrorCode) result;
						op.callback ();
					}
					current_submission = null;
					return;
				}

				parent.maybe_send_pending ();
			}

			private static ssize_t on_data_provider_read (NGHttp2.Session session, int32 stream_id, uint8[] buf,
					ref uint32 data_flags, NGHttp2.DataSource source, void * user_data) {
				var op = (SubmitOperation) source.ptr;

				unowned uint8[] data = op.bytes.get_data ();

				uint remaining = data.length - op.cursor;
				uint n = uint.min (remaining, buf.length);
				Memory.copy (buf, (uint8 *) data + op.cursor, n);

				op.cursor += n;

				if (op.cursor == data.length)
					data_flags |= NGHttp2.DataFlag.EOF;

				return n;
			}

			public void on_data_frame_send () {
				submissions.poll_head ().complete (SUBMITTED);
				current_submission = null;

				maybe_submit_data ();
			}

			public void on_data_frame_not_send (NGHttp2.ErrorCode lib_error_code) {
				submissions.poll_head ().complete (ERROR, lib_error_code);
				current_submission = null;

				maybe_submit_data ();
			}

			private class SubmitOperation {
				public Bytes bytes;
				public SourceFunc callback;

				public State state = PENDING;
				public NGHttp2.ErrorCode error_code;
				public uint cursor = 0;

				public enum State {
					PENDING,
					SUBMITTING,
					SUBMITTED,
					ERROR,
					CANCELLED,
				}

				public SubmitOperation (Bytes bytes, owned SourceFunc callback) {
					this.bytes = bytes;
					this.callback = (owned) callback;
				}

				public void complete (State new_state, NGHttp2.ErrorCode err = -1) {
					if (state != PENDING)
						return;
					state = new_state;
					error_code = err;
					callback ();
				}
			}

			public int on_data_frame_recv_chunk (uint8[] data) {
				incoming_message.append (data);
				return 0;
			}

			public int on_data_frame_recv_end (NGHttp2.Frame frame) {
				XpcMessage? msg;
				size_t size;
				try {
					msg = XpcMessage.try_parse (incoming_message.data, out size);
				} catch (Error e) {
					return -1;
				}
				if (msg == null)
					return 0;
				incoming_message.remove_range (0, (uint) size);

				switch (msg.type) {
					case HEADER:
						parent.on_header (msg, this);
						break;
					case MSG:
						if ((msg.flags & MessageFlags.IS_REPLY) != 0)
							parent.on_reply (msg, this);
						else if ((msg.flags & (MessageFlags.WANTS_REPLY | MessageFlags.IS_REPLY)) == 0)
							parent.message (msg);
						break;
					case PING:
						break;
				}

				return 0;
			}
		}
	}

	public class PeerInfo {
		public Variant? metadata;
	}

	public class XpcMessageBuilder : Object {
		private MessageType message_type;
		private MessageFlags message_flags = NONE;
		private uint64 message_id = 0;
		private Bytes? body = null;

		public XpcMessageBuilder (MessageType message_type) {
			this.message_type = message_type;
		}

		public unowned XpcMessageBuilder add_flags (MessageFlags flags) {
			message_flags = flags;
			return this;
		}

		public unowned XpcMessageBuilder add_id (uint64 id) {
			message_id = id;
			return this;
		}

		public unowned XpcMessageBuilder add_body (Bytes b) {
			body = b;
			return this;
		}

		public Bytes build () {
			var builder = new BufferBuilder (LITTLE_ENDIAN)
				.append_uint32 (XpcMessage.MAGIC)
				.append_uint8 (XpcMessage.PROTOCOL_VERSION)
				.append_uint8 (message_type)
				.append_uint16 (message_flags)
				.append_uint64 ((body != null) ? body.length : 0)
				.append_uint64 (message_id);

			if (body != null)
				builder.append_bytes (body);

			return builder.build ();
		}
	}

	public class XpcMessage {
		public MessageType type;
		public MessageFlags flags;
		public uint64 id;
		public Variant? body;

		public const uint32 MAGIC = 0x29b00b92;
		public const uint8 PROTOCOL_VERSION = 1;
		public const size_t HEADER_SIZE = 24;
		public const size_t MAX_SIZE = (128 * 1024 * 1024) - 1;

		public static XpcMessage parse (uint8[] data) throws Error {
			size_t size;
			var msg = try_parse (data, out size);
			if (msg == null)
				throw new Error.INVALID_ARGUMENT ("XpcMessage is truncated");
			return msg;
		}

		public static XpcMessage? try_parse (uint8[] data, out size_t size) throws Error {
			if (data.length < HEADER_SIZE) {
				size = HEADER_SIZE;
				return null;
			}

			var buf = new Buffer (new Bytes.static (data), LITTLE_ENDIAN);

			var magic = buf.read_uint32 (0);
			if (magic != MAGIC)
				throw new Error.INVALID_ARGUMENT ("Invalid message: bad magic (0x%08x)", magic);

			var protocol_version = buf.read_uint8 (4);
			if (protocol_version != PROTOCOL_VERSION)
				throw new Error.INVALID_ARGUMENT ("Invalid message: unsupported protocol version (%u)", protocol_version);

			var raw_message_type = buf.read_uint8 (5);
			var message_type_class = (EnumClass) typeof (MessageType).class_ref ();
			if (message_type_class.get_value (raw_message_type) == null)
				throw new Error.INVALID_ARGUMENT ("Invalid message: unsupported message type (0x%x)", raw_message_type);
			var message_type = (MessageType) raw_message_type;

			MessageFlags message_flags = (MessageFlags) buf.read_uint16 (6);

			Variant? body = null;
			uint64 message_size = buf.read_uint64 (8);
			size = HEADER_SIZE + (size_t) message_size;
			if (message_size != 0) {
				if (message_size > MAX_SIZE) {
					throw new Error.INVALID_ARGUMENT ("Invalid message: too large (%" + int64.FORMAT_MODIFIER + "u)",
						message_size);
				}
				if (data.length - HEADER_SIZE < message_size)
					return null;
				body = XpcBodyParser.parse (data[HEADER_SIZE:HEADER_SIZE + message_size]);
			}

			uint64 message_id = buf.read_uint64 (16);

			return new XpcMessage (message_type, message_flags, message_id, body);
		}

		private XpcMessage (MessageType type, MessageFlags flags, uint64 id, Variant? body) {
			this.type = type;
			this.flags = flags;
			this.id = id;
			this.body = body;
		}
	}

	public enum MessageType {
		HEADER,
		MSG,
		PING;

		public static MessageType from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<MessageType> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<MessageType> (this);
		}
	}

	[Flags]
	public enum MessageFlags {
		NONE				= 0,
		WANTS_REPLY			= (1 << 0),
		IS_REPLY			= (1 << 1),
		HEADER_OPENS_STREAM_TX		= (1 << 4),
		HEADER_OPENS_STREAM_RX		= (1 << 5),
		HEADER_OPENS_REPLY_CHANNEL	= (1 << 6);

		public string print () {
			uint remainder = this;
			if (remainder == 0)
				return "NONE";

			var result = new StringBuilder.sized (128);

			var klass = (FlagsClass) typeof (MessageFlags).class_ref ();
			foreach (FlagsValue fv in klass.values) {
				if ((remainder & fv.value) != 0) {
					if (result.len != 0)
						result.append (" | ");
					result.append (fv.value_nick.up ().replace ("-", "_"));
					remainder &= ~fv.value;
				}
			}

			if (remainder != 0) {
				if (result.len != 0)
					result.append (" | ");
				result.append_printf ("0x%04x", remainder);
			}

			return result.str;
		}
	}

	public class XpcBodyBuilder : XpcObjectBuilder {
		public XpcBodyBuilder () {
			base ();

			builder
				.append_uint32 (SerializedXpcObject.MAGIC)
				.append_uint32 (SerializedXpcObject.VERSION);
		}
	}

	public class XpcObjectBuilder : Object, ObjectBuilder {
		protected BufferBuilder builder = new BufferBuilder (LITTLE_ENDIAN);
		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		public XpcObjectBuilder () {
			push_scope (new Scope (ROOT));
		}

		public unowned ObjectBuilder begin_dictionary () {
			begin_object (DICTIONARY);

			size_t size_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_entries_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new DictionaryScope (size_offset, num_entries_offset));

			return this;
		}

		public unowned ObjectBuilder set_member_name (string name) {
			builder
				.append_string (name)
				.align (4);

			return this;
		}

		public unowned ObjectBuilder end_dictionary () {
			DictionaryScope scope = pop_scope ();

			uint32 size = (uint32) (builder.offset - scope.num_entries_offset);
			builder.write_uint32 (scope.size_offset, size);

			builder.write_uint32 (scope.num_entries_offset, scope.num_objects);

			return this;
		}

		public unowned ObjectBuilder begin_array () {
			begin_object (ARRAY);

			size_t size_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_elements_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new ArrayScope (size_offset, num_elements_offset));

			return this;
		}

		public unowned ObjectBuilder end_array () {
			ArrayScope scope = pop_scope ();

			uint32 size = (uint32) (builder.offset - scope.num_elements_offset);
			builder.write_uint32 (scope.size_offset, size);

			builder.write_uint32 (scope.num_elements_offset, scope.num_objects);

			return this;
		}

		public unowned ObjectBuilder add_null_value () {
			begin_object (NULL);
			return this;
		}

		public unowned ObjectBuilder add_bool_value (bool val) {
			begin_object (BOOL).append_uint32 ((uint32) val);
			return this;
		}

		public unowned ObjectBuilder add_int64_value (int64 val) {
			begin_object (INT64).append_int64 (val);
			return this;
		}

		public unowned ObjectBuilder add_uint64_value (uint64 val) {
			begin_object (UINT64).append_uint64 (val);
			return this;
		}

		public unowned ObjectBuilder add_data_value (Bytes val) {
			begin_object (DATA)
				.append_uint32 (val.length)
				.append_bytes (val)
				.align (4);
			return this;
		}

		public unowned ObjectBuilder add_string_value (string val) {
			begin_object (STRING)
				.append_uint32 (val.length + 1)
				.append_string (val)
				.align (4);
			return this;
		}

		public unowned ObjectBuilder add_uuid_value (uint8[] val) {
			assert (val.length == 16);
			begin_object (UUID).append_data (val);
			return this;
		}

		public unowned ObjectBuilder add_raw_value (Bytes val) {
			peek_scope ().num_objects++;
			builder.append_bytes (val);
			return this;
		}

		private unowned BufferBuilder begin_object (ObjectType type) {
			peek_scope ().num_objects++;
			return builder.append_uint32 (type);
		}

		public Bytes build () {
			return builder.build ();
		}

		private void push_scope (Scope scope) {
			scopes.offer_tail (scope);
		}

		private Scope peek_scope () {
			return scopes.peek_tail ();
		}

		private T pop_scope<T> () {
			return (T) scopes.poll_tail ();
		}

		private class Scope {
			public Kind kind;
			public uint32 num_objects = 0;

			public enum Kind {
				ROOT,
				DICTIONARY,
				ARRAY,
			}

			public Scope (Kind kind) {
				this.kind = kind;
			}
		}

		private class DictionaryScope : Scope {
			public size_t size_offset;
			public size_t num_entries_offset;

			public DictionaryScope (size_t size_offset, size_t num_entries_offset) {
				base (DICTIONARY);
				this.size_offset = size_offset;
				this.num_entries_offset = num_entries_offset;
			}
		}

		private class ArrayScope : Scope {
			public size_t size_offset;
			public size_t num_elements_offset;

			public ArrayScope (size_t size_offset, size_t num_elements_offset) {
				base (DICTIONARY);
				this.size_offset = size_offset;
				this.num_elements_offset = num_elements_offset;
			}
		}
	}

	private enum ObjectType {
		NULL		= 0x1000,
		BOOL		= 0x2000,
		INT64		= 0x3000,
		UINT64		= 0x4000,
		DATA		= 0x8000,
		STRING		= 0x9000,
		UUID		= 0xa000,
		ARRAY		= 0xe000,
		DICTIONARY	= 0xf000,
	}

	private class XpcBodyParser {
		public static Variant parse (uint8[] data) throws Error {
			if (data.length < 12)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: truncated");

			var buf = new Buffer (new Bytes.static (data), LITTLE_ENDIAN);

			var magic = buf.read_uint32 (0);
			if (magic != SerializedXpcObject.MAGIC)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: bad magic (0x%08x)", magic);

			var version = buf.read_uint8 (4);
			if (version != SerializedXpcObject.VERSION)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: unsupported version (%u)", version);

			var parser = new XpcObjectParser (buf, 8);
			return parser.read_object ();
		}
	}

	private class XpcObjectParser {
		private Buffer buf;
		private size_t cursor;
		private EnumClass object_type_class;

		public XpcObjectParser (Buffer buf, uint cursor) {
			this.buf = buf;
			this.cursor = cursor;
			this.object_type_class = (EnumClass) typeof (ObjectType).class_ref ();
		}

		public Variant read_object () throws Error {
			var raw_type = read_raw_uint32 ();
			if (object_type_class.get_value ((int) raw_type) == null)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: unsupported type (0x%x)", raw_type);
			var type = (ObjectType) raw_type;

			switch (type) {
				case NULL:
					return new Variant.maybe (VariantType.VARIANT, null);
				case BOOL:
					return new Variant.boolean (read_raw_uint32 () != 0);
				case INT64:
					return new Variant.int64 (read_raw_int64 ());
				case UINT64:
					return new Variant.uint64 (read_raw_uint64 ());
				case DATA:
					return read_data ();
				case STRING:
					return read_string ();
				case UUID:
					return read_uuid ();
				case ARRAY:
					return read_array ();
				case DICTIONARY:
					return read_dictionary ();
				default:
					assert_not_reached ();
			}
		}

		private Variant read_data () throws Error {
			var size = read_raw_uint32 ();

			var bytes = read_raw_bytes (size);
			align (4);

			return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
		}

		private Variant read_string () throws Error {
			var size = read_raw_uint32 ();

			var str = buf.read_string (cursor);
			cursor += size;
			align (4);

			return new Variant.string (str);
		}

		private Variant read_uuid () throws Error {
			uint8[] uuid = read_raw_bytes (16).get_data ();
			return new Variant.string ("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X".printf (
				uuid[0], uuid[1], uuid[2], uuid[3],
				uuid[4], uuid[5],
				uuid[6], uuid[7],
				uuid[8], uuid[9],
				uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]));
		}

		private Variant read_array () throws Error {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));

			var size = read_raw_uint32 ();
			size_t num_elements_offset = cursor;
			var num_elements = read_raw_uint32 ();

			for (uint32 i = 0; i != num_elements; i++)
				builder.add ("v", read_object ());

			cursor = num_elements_offset;
			skip (size);

			return builder.end ();
		}

		private Variant read_dictionary () throws Error {
			var builder = new VariantBuilder (VariantType.VARDICT);

			var size = read_raw_uint32 ();
			size_t num_entries_offset = cursor;
			var num_entries = read_raw_uint32 ();

			for (uint32 i = 0; i != num_entries; i++) {
				string key = buf.read_string (cursor);
				skip (key.length + 1);
				align (4);

				Variant val = read_object ();

				builder.add ("{sv}", key, val);
			}

			cursor = num_entries_offset;
			skip (size);

			return builder.end ();
		}

		private uint32 read_raw_uint32 () throws Error {
			check_available (sizeof (uint32));
			var result = buf.read_uint32 (cursor);
			cursor += sizeof (uint32);
			return result;
		}

		private int64 read_raw_int64 () throws Error {
			check_available (sizeof (int64));
			var result = buf.read_int64 (cursor);
			cursor += sizeof (int64);
			return result;
		}

		private uint64 read_raw_uint64 () throws Error {
			check_available (sizeof (uint64));
			var result = buf.read_uint64 (cursor);
			cursor += sizeof (uint64);
			return result;
		}

		private Bytes read_raw_bytes (size_t n) throws Error {
			check_available (n);
			Bytes result = buf.bytes[cursor:cursor + n];
			cursor += n;
			return result;
		}

		private void skip (size_t n) throws Error {
			check_available (n);
			cursor += n;
		}

		private void align (size_t n) throws Error {
			size_t remainder = cursor % n;
			if (remainder != 0)
				skip (n - remainder);
		}

		private void check_available (size_t required) throws Error {
			size_t available = buf.bytes.get_size () - cursor;
			if (available < required)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: truncated");
		}
	}

	namespace SerializedXpcObject {
		public const uint32 MAGIC = 0x42133742;
		public const uint32 VERSION = 5;
	}

	private Key make_keypair (KeyType type) {
		var ctx = new KeyContext.for_key_type (type);
		ctx.keygen_init ();

		Key? keypair = null;
		ctx.keygen (ref keypair);

		return keypair;
	}

	private Bytes get_raw_public_key (Key key) {
		size_t size = 0;
		key.get_raw_public_key (null, ref size);

		var result = new uint8[size];
		key.get_raw_public_key (result, ref size);

		return new Bytes.take ((owned) result);
	}

	private Bytes get_raw_private_key (Key key) {
		size_t size = 0;
		key.get_raw_private_key (null, ref size);

		var result = new uint8[size];
		key.get_raw_private_key (result, ref size);

		return new Bytes.take ((owned) result);
	}

	private string make_host_identifier () {
		var checksum = new Checksum (MD5);

		const uint8 uuid_version = 3;
		const uint8 dns_namespace[] = { 0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 };
		checksum.update (dns_namespace, dns_namespace.length);

		unowned uint8[] host_name = Environment.get_host_name ().data;
		checksum.update (host_name, host_name.length);

		uint8 uuid[16];
		size_t len = uuid.length;
		checksum.get_digest (uuid, ref len);

		uuid[6] = (uuid_version << 4) | (uuid[6] & 0xf);
		uuid[8] = 0x80 | (uuid[8] & 0x3f);

		var result = new StringBuilder.sized (36);
		for (var i = 0; i != uuid.length; i++) {
			result.append_printf ("%02X", uuid[i]);
			switch (i) {
				case 3:
				case 5:
				case 7:
				case 9:
					result.append_c ('-');
					break;
			}
		}

		return result.str;
	}

	private uint8[] make_random_v4_uuid () {
		uint8 uuid[16];
		OpenSSL.Rng.generate (uuid);

		const uint8 uuid_version = 4;
		uuid[6] = (uuid_version << 4) | (uuid[6] & 0xf);
		uuid[8] = 0x80 | (uuid[8] & 0x3f);

		return uuid;
	}
}

"""


```