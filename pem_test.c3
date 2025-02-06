module encoding::pem_test;

import encoding::pem;

import std::io;

const PEM =
`-----BEGIN PRIVACY-ENHANCED MESSAGE-----
Proc-Type: 4,ENCRYPTED
Content-Domain: RFC822
DEK-Info: DES-CBC,F8143EDE5960C597
Originator-ID-Symmetric: linn@zendia.enet.dec.com,,
Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3
Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,
          B70665BB9BF7CBCDA60195DB94F727D3
	  anotherline
Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4
Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,
          E2EF532C65CBCFF79F83A2658132DB47

aGVsbG8gdGhpcyBpcyBqdXN0IGEgbG9uZyBsaW5lIGZvciBiYXNlNjQgZW5jb2Rp
bmcsIHBhZGRpbmc/Cg==
-----END PRIVACY-ENHANCED MESSAGE-----`;

fn void test_pem_block() @test
{
	Parser p;
	p.init(PEM);

	PemBlock b = p.pem_block(allocator::heap())!!;
	defer b.free();

	String want_type = "PRIVACY-ENHANCED MESSAGE";
	assert(b.type == want_type, "parser: failed to get type: got: %s, want: %s", b.type, want_type);

	char[] want_bytes = "hello this is just a long line for base64 encoding, padding?\n";
	assert(b.bytes.len == want_bytes.len, "len does not match; got: %d, want: %d", b.bytes.len, want_bytes.len);
	assert(b.bytes == want_bytes, "parser: failed to get decoded body: got: '%s', want: '%s'", (String)b.bytes, (String)want_bytes);
}

const String[*] PEMTESTS = {
`text before the block
-----BEGIN PEM-----

dGVzdA==
-----END PEM-----
text after the block
`,
};

fn void test_pem() @test
{
	foreach (text : PEMTESTS)
	{
		Parser p;
		p.init(text);

		PemBlock b = p.pem_block(allocator::heap())!!;
		defer b.free();

		String want_type = "PEM";
		assert(b.type == want_type, "parser: failed to get type: got: %s, want: %s", b.type, want_type);

		char[] want_bytes = "test";
		assert(b.bytes.len == want_bytes.len, "len does not match; got: %d (%s), want: %d (%s)", b.bytes.len, (String)b.bytes, want_bytes.len, (String)want_bytes);
		assert(b.bytes == want_bytes, "parser: failed to get decoded body: got: '%s', want: '%s'", (String)b.bytes, (String)want_bytes);
	}
}

struct GetlineTest
{
	String in;
	String[] out;
}

fn void test_getline() @test
{
	GetlineTest[] tests = {
		{
			.in = "abc\ndef\n",
			.out = {"abc","def"},
		},
		{
			.in = "abc\r\ndef\r\n",
			.out = {"abc","def"},
		},
		{
			.in = "abc\ndef",
			.out = {"abc","def"},
		},
		{
			.in = "abc\n\ndef",
			.out = {"abc", "", "def"},
		},
		{
			.in = "abc\n\r\ndef",
			.out = {"abc", "", "def"},
		},
	};

	Parser p;
	foreach (n, t : tests)
	{
		p.init(t.in);
		String got;
		// io::printfn("readline: '%s'", t.in);
		for (int i = 0; i < t.out.len; i++)
		{
			got = p.getline()!!;
			assert(got == t.out[i], "test [%d]: getline error: "
				"got: '%s', want '%s'", n+1, got, t.out[i]);
		}
	}
}
