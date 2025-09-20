## TCP2QUIC
TCP is so widely used, however QUIC may have a better performance. For softwares which use protocols built on TCP, this program helps them take FULL advantage of QUIC.

```text
 tcp                             quic                              tcp
 ===                            ======                             ===
        +-------------------+              +-------------------+
        |                   |              |                   |
+------->                   +-------------->                   +------->
        |   tcp2quic (c)    |              |   tcp2quic (s)    |
<-------+                   <--------------+                   <-------+
        |                   |              |                   |
        +-------------------+              +-------------------+
```

## Usage

```shell
tcp2quic <local_addr> <remote_addr> <options>
```

## Examples

tcp ⇋ quic --- quic ⇋ tcp:

```shell
# Client: TCP -> QUIC
tcp2quic -c 127.0.0.1:9001 127.0.0.1:9000 "quic;sni=localhost;insecure"

# Server: QUIC -> TCP
tcp2quic -s 127.0.0.1:9000 127.0.0.1:8080 "quic;servername=localhost"
```

## Security
The server generates self-signed certificates automatically with the specified common name (default: "localhost").

**Security modes:**
- **Default mode**: Uses system root certificates for verification
- **Insecure mode**: Skips certificate verification (use `insecure` option)

0-RTT is enabled by default for performance, which may be vulnerable to replay attacks in untrusted environments.

