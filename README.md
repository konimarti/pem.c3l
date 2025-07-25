## PEM data encoding for C3

Handle PEM file format in C3. Most common uses for PEM encoding is for TLS
keys. Compliant with RFC 1421.

API overview:

```cpp
import encoding::pem;
import std::io;

// decode a PEM block from an InStream
fn PemBlock? decode(InStream s, Allocator allocator = mem)
fn PemBlock? tdecode(InSream s)

// PemBlock
struct PemBlock
{
	String    label;
	Headers   headers;
	char[]    decoded;
	Allocator allocator;
}
fn void PemBlock.free(&self)
```

### Example

```cpp
module app;

import encoding::pem;
import std::io;

// openssl genrsa -out private-key.pem 1024
const PEM_TEXT = `
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANDJpG3QhJtrwkDp
HU5qOdiY/PjUJTpl1MFzy/KBpfvsfzIvnYWYQiH7Y/DLLXE/J350ggbisw/PezfX
DtEvBWDfyn+GUY1yWdtwqgPVYhuTlS5Um8WeqhAQH5wtWw6r3ORS+Ypy5dNeW5dd
p4iGdjLzFoqf228n/2OK+tqiQ3dlAgMBAAECgYEAipKagIwZxzHRHtXZrpbQR9La
a6gaAVVezPq3DQBBkx/XGA8ERIvWsMkx/rpLMdORudtIBZvm7oJtrJUe73V+4iaK
2mqBAVzkdRy2AEFdNFKrRuPOWnGI9vcC2qcLgG9O/Nx2z0AkL9YPms0AE1sXH/I4
JW7kdWJJEXUcLVSeao0CQQD2AxWgQeO3E/Fmw1Tg9w3WEXc7TUwyY1cpxDTmmSlS
/lEeHvhw1kuE9AWyYQKbKxDDz3mNFfzwhYGuCYON39PnAkEA2UOq9dr0HlaZdzeP
yH+GcKudia0fc9kz3u/BH92H/LZdUoe9cWw+l2cCvi4pPWAOX0dl+I1bJzA4qSuj
kv+w0wJBAM7ATN6AQYZNZmW854qhVql/yDq4fb8jKc/aK7NZKRes0DOGR7lc/97e
ziLZ0LzjdpV5umfOAOOK8C95o2wKniUCQCJZ+pvoxJRPaPBajpdK4nzKBZyRDNoK
S5NCISzin++q/dJgt+lJDhRuKxbawZZ8q4kRBuRnpTPrAepthe1mFBUCQDPYgnov
NKHCYCsRkZgh6TvedOFATUFndQqP302F/EoZfEZDN9mNyCycCemfPQPH9Zd/bDFp
uY855E8ucATSOqY=
-----END PRIVATE KEY-----`;

fn void main()
{
	PemBlock block = pem::decode((ByteReader){}.init(PEM_TEXT))!!;
	defer block.free();

	io::printfn("Label: %s", block.label);
	io::printfn("Text : %s", (String)block.decoded);
}
```

### Installation

Clone the repository with
```git clone http://github.com/konimarti/pem.c3l```
to the `./lib` folder of your C3 project and add the following to
`project.json`:

```json
{
    "dependency-search-paths": [ "lib" ],
    "dependencies": [ "pem" ]
}
```

If you didn't clone it into the `lib` folder, adjust your
`dependency-search-paths` accordingly.
