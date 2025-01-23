Response:
### 功能归纳

该源代码文件 `xpc.vala` 是 Frida 工具中用于处理 XPC（跨进程通信）和配对（Pairing）功能的核心模块。以下是其主要功能的归纳：

1. **配对协议实现**：
   - 实现了设备之间的配对协议，包括密钥交换、会话密钥生成、会话密钥证明等。
   - 使用了 `BigNumber` 类进行大数运算，支持密钥的生成、加密、解密等操作。
   - 通过 `HashBuilder` 类生成哈希值，用于会话密钥的生成和验证。

2. **XPC 通信**：
   - 实现了基于 XPC 的通信协议，支持设备之间的消息传递。
   - 提供了 `XpcPairingTransport` 类，用于处理 XPC 消息的发送和接收。
   - 支持异步操作，允许在通信过程中进行取消操作。

3. **隧道连接**：
   - 实现了隧道连接（TunnelConnection），支持通过 TCP 或 QUIC 协议进行数据传输。
   - 提供了 `TcpTunnelConnection` 和 `QuicTunnelConnection` 类，分别用于处理基于 TCP 和 QUIC 的隧道连接。
   - 支持虚拟网络栈（VirtualNetworkStack），用于处理隧道中的网络数据包。

4. **配对存储**：
   - 提供了 `PairingStore` 类，用于存储和管理配对信息，包括设备的公钥、私钥、IRK（Identity Resolving Key）等。
   - 支持从文件中加载和保存配对信息，确保配对的持久化。

5. **错误处理与调试**：
   - 提供了错误处理机制，支持在通信过程中捕获和处理错误。
   - 通过 `Cancellable` 类支持操作的取消，确保在需要时能够中断通信。

### 二进制底层与 Linux 内核相关

- **大数运算**：`BigNumber` 类用于处理大数运算，这在加密算法中非常常见，尤其是在密钥生成和交换过程中。例如，`BigNumber.mod_exp` 用于计算模幂运算，这在 RSA 等加密算法中非常关键。
- **哈希计算**：`HashBuilder` 类使用了 SHA-512 等哈希算法，用于生成会话密钥和验证数据完整性。哈希算法在加密通信中用于确保数据的完整性和真实性。
- **TLS/SSL 加密**：在 `TcpTunnelConnection` 中，使用了 TLS/SSL 加密来保护通信数据。`TlsClientConnection` 类封装了 OpenSSL 的 SSL 上下文，用于处理加密通信。

### LLDB 调试示例

假设你想调试 `TcpTunnelConnection` 类的 `init_async` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令

```lldb
b TcpTunnelConnection::init_async
r
```

#### LLDB Python 脚本

```python
import lldb

def init_async_breakpoint(frame, bp_loc, dict):
    print("Hit init_async breakpoint")
    return True

def main():
    debugger = lldb.SBDebugger.Create()
    target = debugger.CreateTarget("frida")
    if not target:
        print("Failed to create target")
        return

    breakpoint = target.BreakpointCreateByName("TcpTunnelConnection::init_async")
    if not breakpoint.IsValid():
        print("Failed to set breakpoint")
        return

    breakpoint.SetScriptCallbackFunction("init_async_breakpoint")

    process = target.LaunchSimple(None, None, os.getcwd())
    if not process:
        print("Failed to launch process")
        return

    process.Continue()

if __name__ == "__main__":
    main()
```

### 假设输入与输出

假设输入为设备的公钥和私钥，输出为生成的会话密钥和会话密钥证明。

- **输入**：
  - `remote_pubkey`: 远程设备的公钥
  - `local_privkey`: 本地设备的私钥
  - `password_hash`: 密码哈希值

- **输出**：
  - `session_key`: 生成的会话密钥
  - `session_key_proof`: 会话密钥的证明

### 常见使用错误

1. **密钥不匹配**：如果远程设备的公钥与本地设备的私钥不匹配，会导致会话密钥生成失败。用户需要确保配对的设备使用正确的密钥。
2. **哈希计算错误**：如果哈希计算过程中输入的数据不正确，生成的会话密钥证明将无法通过验证。用户需要确保输入的数据（如用户名、盐值等）正确无误。
3. **通信中断**：在 XPC 通信过程中，如果网络中断或设备断开连接，会导致通信失败。用户需要确保网络连接稳定。

### 用户操作步骤

1. **启动配对**：用户通过 Frida 工具启动设备配对流程，选择要配对的设备。
2. **密钥交换**：Frida 工具会自动交换设备的公钥和私钥，生成会话密钥。
3. **验证配对**：Frida 工具会验证会话密钥的证明，确保配对成功。
4. **建立隧道连接**：配对成功后，Frida 工具会建立隧道连接，允许设备之间的数据传输。

通过这些步骤，用户可以逐步完成设备的配对和通信，Frida 工具会在每个步骤中处理相关的加密和通信逻辑。
### 提示词
```
这是目录为frida/subprojects/frida-core/src/fruity/xpc.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
);
				var baze = new BigNumber ();
				BigNumber.sub (baze, remote_pubkey, val);

				var exp = new BigNumber ();
				BigNumber.mul (val, common_secret, password_hash, bn_ctx);
				BigNumber.add (exp, local_privkey, val);

				BigNumber.mod_exp (val, baze, exp, prime, bn_ctx);

				return val;
			}

			private static Bytes compute_session_key (BigNumber premaster_secret) {
				return new HashBuilder ()
					.add_number (premaster_secret)
					.build_digest ();
			}

			private Bytes compute_session_key_proof (Bytes session_key, BigNumber remote_pubkey, Bytes salt) {
				Bytes prime_hash = new HashBuilder ().add_number (prime).build_digest ();
				Bytes generator_hash = new HashBuilder ().add_number (generator).build_digest ();
				uint8 prime_and_generator_xored[64];
				unowned uint8[] left = prime_hash.get_data ();
				unowned uint8[] right = generator_hash.get_data ();
				for (var i = 0; i != prime_and_generator_xored.length; i++)
					prime_and_generator_xored[i] = left[i] ^ right[i];

				return new HashBuilder ()
					.add_data (prime_and_generator_xored)
					.add_bytes (new HashBuilder ().add_string (username).build_digest ())
					.add_bytes (salt)
					.add_number (local_pubkey)
					.add_number (remote_pubkey)
					.add_bytes (session_key)
					.build_digest ();
			}

			private Bytes compute_session_key_proof_hash (Bytes key_proof, Bytes key) {
				return new HashBuilder ()
					.add_number (local_pubkey)
					.add_bytes (key_proof)
					.add_bytes (key)
					.build_digest ();
			}

			private class HashBuilder {
				private Checksum checksum = new Checksum (SHA512);

				public unowned HashBuilder add_number (BigNumber val) {
					var buf = new uint8[val.num_bytes ()];
					val.to_big_endian (buf);
					return add_data (buf);
				}

				public unowned HashBuilder add_number_padded (BigNumber val) {
					uint8 buf[384];
					val.to_big_endian_padded (buf);
					return add_data (buf);
				}

				public unowned HashBuilder add_string (string val) {
					return add_data (val.data);
				}

				public unowned HashBuilder add_bytes (Bytes val) {
					return add_data (val.get_data ());
				}

				public unowned HashBuilder add_data (uint8[] val) {
					checksum.update (val, val.length);
					return this;
				}

				public Bytes build_digest () {
					var buf = new uint8[64];
					size_t len = buf.length;
					checksum.get_digest (buf, ref len);
					return new Bytes.take ((owned) buf);
				}

				public BigNumber build_number () {
					uint8 buf[64];
					size_t len = buf.length;
					checksum.get_digest (buf, ref len);
					return new BigNumber.from_big_endian (buf);
				}
			}
		}
	}

	public interface PairingTransport : Object {
		public signal void close (Error? error);
		public signal void message (ObjectReader reader);

		public abstract async void open (Cancellable? cancellable) throws Error, IOError;
		public abstract void cancel ();

		public abstract ObjectBuilder make_object_builder ();
		public abstract void post (Bytes message);
	}

	public class XpcPairingTransport : Object, PairingTransport {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private Cancellable io_cancellable = new Cancellable ();

		public XpcPairingTransport (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			connection.activate ();

			yield connection.wait_until_ready (cancellable);
		}

		public void cancel () {
			io_cancellable.cancel ();

			connection.cancel ();
		}

		public ObjectBuilder make_object_builder () {
			return new XpcObjectBuilder ();
		}

		public void post (Bytes msg) {
			connection.post.begin (
				new XpcBodyBuilder ()
					.begin_dictionary ()
						.set_member_name ("mangledTypeName")
						.add_string_value ("RemotePairing.ControlChannelMessageEnvelope")
						.set_member_name ("value")
						.add_raw_value (msg)
					.end_dictionary ()
					.build (),
				io_cancellable);
		}

		private void on_close (Error? error) {
			close (error);
		}

		private void on_message (XpcMessage msg) {
			if (msg.body == null)
				return;

			var reader = new VariantReader (msg.body);
			try {
				string type_name = reader.read_member ("mangledTypeName").get_string_value ();
				if (type_name != "RemotePairingDevice.ControlChannelMessageEnvelope")
					return;
				reader.end_member ();

				reader.read_member ("value");

				message (reader);
			} catch (Error e) {
			}
		}
	}

	public class PlainPairingTransport : Object, PairingTransport {
		public IOStream stream {
			get;
			construct;
		}

		private BufferedInputStream input;
		private OutputStream output;

		private ByteArray pending_output = new ByteArray ();
		private bool writing = false;

		private Cancellable io_cancellable = new Cancellable ();

		public PlainPairingTransport (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = (BufferedInputStream) Object.new (typeof (BufferedInputStream),
				"base-stream", stream.get_input_stream (),
				"close-base-stream", false,
				"buffer-size", 128 * 1024);
			output = stream.get_output_stream ();
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			process_incoming_messages.begin ();
		}

		public void cancel () {
			io_cancellable.cancel ();
		}

		public ObjectBuilder make_object_builder () {
			return new JsonObjectBuilder ();
		}

		public void post (Bytes msg) {
			Bytes raw_msg = new BufferBuilder (BIG_ENDIAN)
				.append_string ("RPPairing", StringTerminator.NONE)
				.append_uint16 ((uint16) msg.get_size ())
				.append_bytes (msg)
				.build ();
			pending_output.append (raw_msg.get_data ());

			if (!writing) {
				writing = true;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_pending_output.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private async void process_incoming_messages () {
			try {
				while (true) {
					size_t header_size = 11;
					if (input.get_available () < header_size)
						yield fill_until_n_bytes_available (header_size);

					uint8 raw_magic[9];
					input.peek (raw_magic);
					string magic = ((string) raw_magic).make_valid (raw_magic.length);
					if (magic != "RPPairing")
						throw new Error.PROTOCOL ("Invalid message magic: '%s'", magic);

					uint16 body_size = 0;
					unowned uint8[] size_buf = ((uint8[]) &body_size)[:2];
					input.peek (size_buf, raw_magic.length);
					body_size = uint16.from_big_endian (body_size);
					if (body_size < 2)
						throw new Error.PROTOCOL ("Invalid message size");

					size_t full_size = header_size + body_size;
					if (input.get_available () < full_size)
						yield fill_until_n_bytes_available (full_size);

					var raw_json = new uint8[body_size + 1];
					input.peek (raw_json[:body_size], header_size);

					unowned string json = (string) raw_json;
					if (!json.validate ())
						throw new Error.PROTOCOL ("Invalid UTF-8");

					var reader = new JsonObjectReader (json);

					message (reader);

					input.skip (full_size, io_cancellable);
				}
			} catch (GLib.Error e) {
			}

			close (null);
		}

		private async void process_pending_output () {
			while (pending_output.len > 0) {
				uint8[] batch = pending_output.steal ();

				size_t bytes_written;
				try {
					yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
				} catch (GLib.Error e) {
					break;
				}
			}

			writing = false;
		}

		private async void fill_until_n_bytes_available (size_t minimum) throws Error, IOError {
			size_t available = input.get_available ();
			while (available < minimum) {
				if (input.get_buffer_size () < minimum)
					input.set_buffer_size (minimum);

				ssize_t n;
				try {
					n = yield input.fill_async ((ssize_t) (input.get_buffer_size () - available), Priority.DEFAULT,
						io_cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Connection closed");
				}

				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed");

				available += n;
			}
		}
	}

	public class PairingStore {
		public PairingIdentity self_identity {
			get {
				return _self_identity;
			}
		}

		public Gee.Iterable<PairingPeer> peers {
			get {
				return _peers;
			}
		}

		private PairingIdentity _self_identity;
		private Gee.List<PairingPeer> _peers;

		public PairingStore () {
			_self_identity = try_load_identity ();
			if (_self_identity == null) {
				_self_identity = PairingIdentity.make ();
				try {
					save_identity (_self_identity);
				} catch (GLib.Error e) {
				}
			}

			_peers = load_peers ();
		}

		public void add_peer (string identifier, Bytes public_key, Bytes info) throws Error {
			var r = new VariantReader (OpackParser.parse (info));

			Bytes irk = r.read_member ("altIRK").get_data_value ();
			r.end_member ();

			unowned string name = r.read_member ("name").get_string_value ();
			r.end_member ();

			unowned string model = r.read_member ("model").get_string_value ();
			r.end_member ();

			unowned string udid = r.read_member ("remotepairing_udid").get_string_value ();
			r.end_member ();

			var peer = new PairingPeer () {
				identifier = identifier,
				public_key = public_key,
				irk = irk,
				name = name,
				model = model,
				udid = udid,
				info = info,
			};
			_peers.add (peer);

			try {
				save_peer (peer);
			} catch (Error e) {
			}
		}

		public PairingPeer? find_peer_matching_service (PairingServiceDetails service) {
			var mac = OpenSSL.Envelope.MessageAuthCode.fetch (null, OpenSSL.ShortName.siphash);

			size_t hash_size = 8;
			size_t return_size = OpenSSL.ParamReturnSize.UNMODIFIED;
			OpenSSL.Param mac_params[] = {
				{ OpenSSL.Envelope.MessageAuthParameter.SIZE, UNSIGNED_INTEGER,
					(uint8[]) &hash_size, return_size },
				{ null, INTEGER, null, return_size },
			};

			foreach (var peer in _peers) {
				var ctx = new OpenSSL.Envelope.MessageAuthCodeContext (mac);
				ctx.init (peer.irk.get_data (), mac_params);
				ctx.update (service.identifier.data);
				uint8 output[8];
				size_t outlen = 0;
				ctx.final (output, out outlen);

				uint8 tag[6];
				for (uint i = 0; i != 6; i++)
					tag[i] = output[5 - i];

				if (Memory.cmp (tag, service.auth_tag.get_data (), service.auth_tag.get_size ()) == 0)
					return peer;
			}

			return null;
		}

		private static PairingIdentity? try_load_identity () {
			try {
				var plist = new Plist.from_data (query_self_identity_location ().load_bytes ().get_data ());
				return new PairingIdentity () {
					identifier = plist.get_string ("identifier"),
					key = new Key.from_raw_private_key (ED25519, null, plist.get_bytes ("privateKey").get_data ()),
					irk = plist.get_bytes ("irk"),
				};
			} catch (GLib.Error e) {
				return null;
			}
		}

		private static void save_identity (PairingIdentity identity) throws Error {
			var plist = new Plist ();
			plist.set_string ("identifier", identity.identifier);
			plist.set_bytes ("publicKey", get_raw_public_key (identity.key));
			plist.set_bytes ("privateKey", get_raw_private_key (identity.key));
			plist.set_bytes ("irk", identity.irk);
			save_plist (plist, query_self_identity_location ());
		}

		private static Gee.List<PairingPeer> load_peers () {
			var peers = new Gee.ArrayList<PairingPeer> ();

			try {
				var enumerator = query_peers_location ().enumerate_children (FileAttribute.STANDARD_NAME, FileQueryInfoFlags.NONE);
				File? child;
				while (enumerator.iterate (null, out child) && child != null) {
					var plist = new Plist.from_data (child.load_bytes ().get_data ());

					var info = plist.get_bytes ("info");
					var r = new VariantReader (OpackParser.parse (info));
					unowned string udid = r.read_member ("remotepairing_udid").get_string_value ();

					peers.add (new PairingPeer () {
						identifier = plist.get_string ("identifier"),
						public_key = plist.get_bytes ("publicKey"),
						irk = plist.get_bytes ("irk"),
						name = plist.get_string ("name"),
						model = plist.get_string ("model"),
						udid = udid,
						info = info,
					});
				}
			} catch (GLib.Error e) {
			}

			return peers;
		}

		private static void save_peer (PairingPeer peer) throws Error {
			var plist = new Plist ();
			plist.set_string ("identifier", peer.identifier);
			plist.set_bytes ("publicKey", peer.public_key);
			plist.set_bytes ("irk", peer.irk);
			plist.set_string ("name", peer.name);
			plist.set_string ("model", peer.model);
			plist.set_bytes ("info", peer.info);
			save_plist (plist, query_peers_location ().get_child (peer.identifier + ".plist"));
		}

		private static File query_self_identity_location () {
			return query_base_location ().get_child ("self-identity.plist");
		}

		private static File query_peers_location () {
			return query_base_location ().get_child ("peers");
		}

		private static File query_base_location () {
			return File.new_build_filename (Environment.get_user_config_dir (), "frida");
		}

		private static void save_plist (Plist plist, File location) throws Error {
			try {
				location.get_parent ().make_directory_with_parents ();
			} catch (GLib.Error e) {
			}
			try {
				location.replace_contents (plist.to_binary (), null, false, PRIVATE | REPLACE_DESTINATION, null);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	public class PairingIdentity {
		public string identifier;
		public Key key;
		public Bytes irk;

		public static PairingIdentity make () {
			uint8 raw_irk[16];
			Rng.generate (raw_irk);

			return new PairingIdentity () {
				identifier = make_host_identifier (),
				key = make_keypair (ED25519),
				irk = new Bytes (raw_irk),
			};
		}
	}

	public class PairingPeer {
		public string identifier;
		public Bytes public_key;
		public Bytes irk;
		public string name;
		public string model;
		public string udid;
		public Bytes info;
	}

	public class PairingServiceMetadata {
		public string identifier;
		public Bytes auth_tag;

		public static PairingServiceMetadata from_txt_record (Gee.Iterable<string> record) throws Error {
			string? identifier = null;
			Bytes? auth_tag = null;
			foreach (string item in record) {
				string[] tokens = item.split ("=", 2);
				if (tokens.length != 2)
					continue;

				unowned string key = tokens[0];
				unowned string val = tokens[1];
				if (key == "identifier")
					identifier = val;
				else if (key == "authTag")
					auth_tag = new Bytes (Base64.decode (val));
			}
			if (identifier == null || auth_tag == null)
				throw new Error.PROTOCOL ("Missing TXT metadata");

			return new PairingServiceMetadata () {
				identifier = identifier,
				auth_tag = auth_tag,
			};
		}
	}

	public class DeviceOptions {
		public bool allows_pair_setup;
		public bool allows_pinless_pairing;
		public bool allows_promptless_automation_pairing_upgrade;
		public bool allows_sharing_sensitive_info;
		public bool allows_incoming_tunnel_connections;
	}

	public class DeviceInfo {
		public string name;
		public string model;
		public string udid;
		public uint64 ecid;
		public Plist kvs;
	}

	private class PairingParamsBuilder {
		private BufferBuilder builder = new BufferBuilder (LITTLE_ENDIAN);

		public unowned PairingParamsBuilder add_method (uint8 method) {
			begin_param (METHOD, 1)
				.append_uint8 (method);

			return this;
		}

		public unowned PairingParamsBuilder add_identifier (string identifier) {
			begin_param (IDENTIFIER, identifier.data.length)
				.append_data (identifier.data);

			return this;
		}

		public unowned PairingParamsBuilder add_public_key (Key key) {
			return add_raw_public_key (get_raw_public_key (key));
		}

		public unowned PairingParamsBuilder add_raw_public_key (Bytes key) {
			return add_blob (PUBLIC_KEY, key);
		}

		public unowned PairingParamsBuilder add_proof (Bytes proof) {
			return add_blob (PROOF, proof);
		}

		public unowned PairingParamsBuilder add_encrypted_data (Bytes bytes) {
			return add_blob (ENCRYPTED_DATA, bytes);
		}

		public unowned PairingParamsBuilder add_state (uint8 state) {
			begin_param (STATE, 1)
				.append_uint8 (state);

			return this;
		}

		public unowned PairingParamsBuilder add_signature (Bytes signature) {
			return add_blob (SIGNATURE, signature);
		}

		public unowned PairingParamsBuilder add_info (Bytes info) {
			return add_blob (INFO, info);
		}

		private unowned PairingParamsBuilder add_blob (PairingParamType type, Bytes blob) {
			unowned uint8[] data = blob.get_data ();

			uint cursor = 0;
			do {
				uint n = uint.min (data.length - cursor, uint8.MAX);
				begin_param (type, n)
					.append_data (data[cursor:cursor + n]);
				cursor += n;
			} while (cursor != data.length);

			return this;
		}

		private unowned BufferBuilder begin_param (PairingParamType type, size_t size) {
			return builder
				.append_uint8 (type)
				.append_uint8 ((uint8) size);
		}

		public Bytes build () {
			return builder.build ();
		}
	}

	private class PairingParamsParser {
		private BufferReader reader;
		private EnumClass param_type_class;

		public static Variant parse (Bytes pairing_params) throws Error {
			var parser = new PairingParamsParser (pairing_params);
			return parser.read_params ();
		}

		private PairingParamsParser (Bytes bytes) {
			reader = new BufferReader (new Buffer (bytes, LITTLE_ENDIAN));
			param_type_class = (EnumClass) typeof (PairingParamType).class_ref ();
		}

		private Variant read_params () throws Error {
			var byte_array = new VariantType.array (VariantType.BYTE);

			var parameters = new Gee.HashMap<string, Variant> ();
			while (reader.available != 0) {
				var raw_type = reader.read_uint8 ();
				unowned EnumValue? type_enum_val = param_type_class.get_value (raw_type);
				if (type_enum_val == null)
					throw new Error.INVALID_ARGUMENT ("Unsupported pairing parameter type (0x%x)", raw_type);
				var type = (PairingParamType) raw_type;
				unowned string key = type_enum_val.value_nick;

				var val_size = reader.read_uint8 ();
				Variant val;
				switch (type) {
					case IDENTIFIER:
						val = new Variant.string (reader.read_fixed_string (val_size));
						break;
					case STATE:
					case ERROR:
						if (val_size != 1)
							throw new Error.INVALID_ARGUMENT ("Invalid value for '%s': size=%u", key, val_size);
						val = new Variant.byte (reader.read_uint8 ());
						break;
					case RETRY_DELAY: {
						uint16 delay;
						switch (val_size) {
							case 1:
								delay = reader.read_uint8 ();
								break;
							case 2:
								delay = reader.read_uint16 ();
								break;
							default:
								throw new Error.INVALID_ARGUMENT ("Invalid value for 'retry-delay'");
						}
						val = new Variant.uint16 (delay);
						break;
					}
					default: {
						Bytes val_bytes = reader.read_bytes (val_size);
						var val_bytes_copy = new Bytes (val_bytes.get_data ());
						val = Variant.new_from_data (byte_array, val_bytes_copy.get_data (), true, val_bytes_copy);
						break;
					}
				}

				Variant? existing_val = parameters[key];
				if (existing_val != null) {
					if (!existing_val.is_of_type (byte_array))
						throw new Error.INVALID_ARGUMENT ("Unable to merge '%s' keys: unsupported type", key);
					Bytes part1 = existing_val.get_data_as_bytes ();
					Bytes part2 = val.get_data_as_bytes ();
					var combined = new ByteArray.sized ((uint) (part1.get_size () + part2.get_size ()));
					combined.append (part1.get_data ());
					combined.append (part2.get_data ());
					val = Variant.new_from_data (byte_array, combined.data, true, (owned) combined);
				}

				parameters[key] = val;
			}

			var builder = new VariantBuilder (VariantType.VARDICT);
			foreach (var e in parameters.entries)
				builder.add ("{sv}", e.key, e.value);
			return builder.end ();
		}
	}

	private enum PairingParamType {
		METHOD,
		IDENTIFIER,
		SALT,
		PUBLIC_KEY,
		PROOF,
		ENCRYPTED_DATA,
		STATE,
		ERROR,
		RETRY_DELAY /* = 8 */,
		SIGNATURE = 10,
		INFO = 17,
	}

	public interface TunnelConnection : Object {
		public signal void closed ();

		public abstract NetworkStack tunnel_netstack {
			get;
		}

		public abstract InetAddress remote_address {
			get;
		}

		public abstract uint16 remote_rsd_port {
			get;
		}

		public abstract async void close (Cancellable? cancellable) throws IOError;

		protected static Bytes make_handshake_request (size_t mtu) {
			string body = Json.to_string (
				new Json.Builder ()
				.begin_object ()
					.set_member_name ("type")
					.add_string_value ("clientHandshakeRequest")
					.set_member_name ("mtu")
					.add_int_value (mtu)
				.end_object ()
				.get_root (), false);
			return make_request (body.data);
		}

		protected static Bytes make_request (uint8[] body) {
			return new BufferBuilder (BIG_ENDIAN)
				.append_string ("CDTunnel", StringTerminator.NONE)
				.append_uint16 ((uint16) body.length)
				.append_data (body)
				.build ();
		}
	}

	public class TunnelParameters {
		public InetAddress address;
		public uint16 mtu;
		public InetAddress server_address;
		public uint16 server_rsd_port;

		public static TunnelParameters from_json (JsonObjectReader reader) throws Error {
			reader.read_member ("clientParameters");

			reader.read_member ("address");
			string address = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("mtu");
			uint16 mtu = reader.get_uint16_value ();
			reader.end_member ();

			reader.end_member ();

			reader.read_member ("serverAddress");
			string server_address = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("serverRSDPort");
			uint16 server_rsd_port = reader.get_uint16_value ();
			reader.end_member ();

			return new TunnelParameters () {
				address = new InetAddress.from_string (address),
				mtu = (uint16) mtu,
				server_address = new InetAddress.from_string (server_address),
				server_rsd_port = server_rsd_port,
			};
		}
	}

	public sealed class TcpTunnelConnection : Object, TunnelConnection, AsyncInitable {
		public InetSocketAddress address {
			get;
			construct;
		}

		public NetworkStack netstack {
			get;
			construct;
		}

		public NetworkStack tunnel_netstack {
			get {
				return _tunnel_netstack;
			}
		}

		public TunnelKey local_keypair {
			get;
			construct;
		}

		public TunnelKey remote_pubkey {
			get;
			construct;
		}

		public InetAddress remote_address {
			get {
				return tunnel_params.server_address;
			}
		}

		public uint16 remote_rsd_port {
			get {
				return tunnel_params.server_rsd_port;
			}
		}

		private Promise<bool> close_request = new Promise<bool> ();

		private TunnelParameters tunnel_params;
		private VirtualNetworkStack _tunnel_netstack;

		private TlsClientConnection connection;
		private BufferedInputStream input;
		private OutputStream output;

		private ByteArray pending_output = new ByteArray ();
		private bool writing = false;

		private Cancellable io_cancellable = new Cancellable ();

		private const size_t PREFERRED_MTU = 16000;
		private const string PSK_IDENTITY = "com.apple.CoreDevice.TunnelService.Identity";

		public static async TcpTunnelConnection open (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey, Cancellable? cancellable = null) throws Error, IOError {
			var connection = new TcpTunnelConnection (address, netstack, local_keypair, remote_pubkey);

			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return connection;
		}

		private TcpTunnelConnection (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey) {
			Object (
				address: address,
				netstack: netstack,
				local_keypair: local_keypair,
				remote_pubkey: remote_pubkey
			);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var stream = yield netstack.open_tcp_connection (address, cancellable);

			try {
				connection = TlsClientConnection.new (stream, null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			connection.set_data_full ("tcp-tunnel-connection", this, null);
			connection.set_database (null);

			unowned SSL ssl = get_ssl_handle_from_connection (connection);
			ssl.set_cipher_list ("PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA256");
			ssl.set_psk_client_callback ((ssl, hint, identity, psk) => {
				unowned TlsClientConnection conn = (TlsClientConnection) get_connection_from_ssl_handle (ssl);
				TcpTunnelConnection self = conn.get_data ("tcp-tunnel-connection");
				return self.on_psk_request (ssl, hint, identity, psk);
			});

			try {
				yield connection.handshake_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}

			input = (BufferedInputStream) Object.new (typeof (BufferedInputStream),
				"base-stream", connection.get_input_stream (),
				"close-base-stream", false,
				"buffer-size", 128 * 1024);
			output = connection.get_output_stream ();

			post (make_handshake_request (PREFERRED_MTU));

			tunnel_params = TunnelParameters.from_json (yield read_message (cancellable));

			_tunnel_netstack = new VirtualNetworkStack (null, tunnel_params.address, tunnel_params.mtu);
			_tunnel_netstack.outgoing_datagram.connect (post);

			process_incoming_messages.begin ();

			return true;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			try {
				yield close_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private async void process_incoming_messages () {
			try {
				while (true) {
					var datagram = yield read_datagram (io_cancellable);

					_tunnel_netstack.handle_incoming_datagram (datagram);
				}
			} catch (GLib.Error e) {
			}

			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (process_incoming_messages.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield connection.close_async ();
			} catch (GLib.Error e) {
			}

			if (_tunnel_netstack != null)
				_tunnel_netstack.stop ();

			close_request.resolve (true);

			closed ();
		}

		private void post (Bytes bytes) {
			pending_output.append (bytes.get_data ());

			if (!writing) {
				writing = true;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_pending_output.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private async void process_pending_output () {
			while (pending_output.len > 0) {
				uint8[] batch = pending_output.steal ();

				size_t bytes_written;
				try {
					yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
				} catch (GLib.Error e) {
					break;
				}
			}

			writing = false;
		}

		private async JsonObjectReader read_message (Cancellable? cancellable) throws Error, IOError {
			size_t header_size = 10;
			if (input.get_available () < header_size)
				yield fill_until_n_bytes_available (header_size, cancellable);

			uint8 raw_magic[8];
			input.peek (raw_magic);
			string magic = ((string) raw_magic).make_valid (raw_magic.length);
			if (magic != "CDTunnel")
				throw new Error.PROTOCOL ("Invalid message magic: '%s'", magic);

			uint16 body_size = 0;
			unowned uint8[] size_buf = ((uint8[]) &body_size)[:2];
			input.peek (size_buf, raw_magic.length);
			body_size = uint16.from_big_endian (body_size);

			size_t full_size = header_size + body_size;
			if (input.get_available () < full_size)
				yield fill_until_n_bytes_available (full_size, cancellable);

			var body = new uint8[body_size + 1];
			input.peek (body[:body_size], header_size);
			body.length = body_size;

			input.skip (full_size, cancellable);

			unowned string json = (string) body;
			if (!json.validate ())
				throw new Error.PROTOCOL ("Invalid UTF-8");

			return new JsonObjectReader (json);
		}

		private async Bytes read_datagram (Cancellable? cancellable) throws Error, IOError {
			size_t header_size = 40;
			if (input.get_available () < header_size)
				yield fill_until_n_bytes_available (header_size, cancellable);

			uint16 payload_size = 0;
			unowned uint8[] size_buf = ((uint8[]) &payload_size)[:2];
			input.peek (size_buf, 4);
			payload_size = uint16.from_big_endian (payload_size);

			size_t full_size = header_size + payload_size;
			if (input.get_available () < full_size)
				yield fill_until_n_bytes_available (full_size, cancellable);

			var datagram = new uint8[full_size];
			input.read (datagram, cancellable);

			return new Bytes.take ((owned) datagram);
		}

		private async void fill_until_n_bytes_available (size_t minimum, Cancellable? cancellable) throws Error, IOError {
			size_t available = input.get_available ();
			while (available < minimum) {
				if (input.get_buffer_size () < minimum)
					input.set_buffer_size (minimum);

				ssize_t n;
				try {
					n = yield input.fill_async ((ssize_t) (input.get_buffer_size () - available), Priority.DEFAULT,
						cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Connection closed");
				}

				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed");

				available += n;
			}
		}

		private uint on_psk_request (SSL ssl, string? hint, char[] identity, uint8[] psk) {
			Memory.copy (identity, PSK_IDENTITY.data, PSK_IDENTITY.data.length);

			var key = get_raw_private_key (local_keypair.handle).get_data ();
			Memory.copy (psk, key, key.length);

			return key.length;
		}

		[CCode (cname = "g_tls_connection_openssl_get_ssl")]
		private extern static unowned SSL get_ssl_handle_from_connection (void * connection);

		[CCode (cname = "g_tls_connection_openssl_get_connection_from_ssl")]
		private extern static void * get_connection_from_ssl_handle (SSL ssl);
	}

	public sealed class QuicTunnelConnection : Object, TunnelConnection, AsyncInitable {
		public InetSocketAddress address {
			get;
			construct;
		}

		public NetworkStack netstack {
			get;
			construct;
		}

		public NetworkStack tunnel_netstack {
			get {
				return _tunnel_netstack;
			}
		}

		public TunnelKey local_keypair {
			get;
			construct;
		}

		public TunnelKey remote_pubkey {
			get;
			construct;
		}

		public InetAddress remote_address {
			get {
				return tunnel_params.server_address;
			}
		}

		public uint16 remote_rsd_port {
			get {
				return tunnel_params.server_rsd_port;
			}
		}

		private State state = ACTIVE;
		private Promise<bool> establish_request = new Promise<bool> ();
		private Promise<bool> close_request = new Promise<bool> ();

		private Stream? control_stream;
		private TunnelParameters tunnel_params;
		private VirtualNetworkStack? _tunnel_netstack;

		private Gee.Map<int64?, Stream> streams = new Gee.HashMap<int64?, Stream> (Numeric.int64_hash, Numeric.int64_equal);
		private Gee.Queue<Bytes> tx_datagrams = new Gee.ArrayQueue<Bytes> ();

		private DatagramBasedSource? rx_source;
		private uint8[] rx_buf = new uint8[MAX_UDP_PAYLOAD_SIZE];
		private uint8[] tx_buf = new uint8[MAX_UDP_PAYLOAD_SIZE];
		private Source? write_idle;
		private Source? expiry_timer;

		private UdpSocket? socket;
		private uint8[] raw_local_address;
		private NGTcp2.Connection? connection;
		private NGTcp2.Crypto.ConnectionRef connection_ref;
		private OpenSSL.SSLContext ssl_ctx;
		private OpenSSL.SSL ssl;

		private MainContext main_context;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			ACTIVE,
			CLOSE_SCHEDULED,
			CLOSE_WRITTEN,
		}

		private const string ALPN = "\x1bRemotePairingTunnelProtocol";

		private const size_t NETWORK_MTU = 1500;

		private const size_t ETHERNET_HEADER_SIZE = 14;
		private const size_t IPV6_HEADER_SIZE = 40;
		private const size_t UDP_HEADER_SIZE = 8;
		private const size_t QUIC_HEADER_MAX_SIZE = 38;

		private const size_t MAX_UDP_PAYLOAD_SIZE = NETWORK_MTU - ETHERNET_HEADER_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE;
		private const size_t PREFERRED_MTU = MAX_UDP_PAYLOAD_SIZE - QUIC_HEADER_MAX_SIZE;

		private const size_t MAX_QUIC_DATAGRAM_SIZE = 14000;
		private const NGTcp2.Duration KEEP_ALIVE_TIMEOUT = 15ULL * NGTcp2.SECONDS;

		public static async QuicTunnelConnection open (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey, Cancellable? cancellable = null) throws Error, IOError {
			var connection = new QuicTunnelConnection (address, netst
```