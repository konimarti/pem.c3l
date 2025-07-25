module encoding::pem_test @test;

import encoding::pem;
import std::io;

 struct TestCase
{
	String input;
	String want_label;
	String want_decoded;
	usz header_len;
}

TestCase[*] pemtests = {
	{
		.input =
`text before the block
-----BEGIN PEM-----

dGVzdA==
-----END PEM-----
text after the block
`,
	.want_label = "PEM",
	.want_decoded = "test",
	.header_len = 0
	},
	{
		.input =
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
-----END PRIVACY-ENHANCED MESSAGE-----`,
	.want_label = "PRIVACY-ENHANCED MESSAGE",
	.want_decoded = "hello this is just a long line for base64 encoding, padding?\n",
	.header_len = 7
	},
};

fn void test_pem_blocks() => @assert_leak()
{
	foreach (tc : pemtests)
	{
		PemParser p = { (ByteReader){}.init(tc.input) };

		PemBlock b = p.next()!!;
		defer b.free();

		assert(b.label == tc.want_label,
			"parser: failed to get label: got: %s, want: %s", b.label, tc.want_label);

		assert(b.headers.len() == tc.header_len, "parser: header lengths does not match");

		assert(b.decoded.len == tc.want_decoded.len,
			"len does not match; got: %d (%s), want: %d (%s)", b.decoded.len, (String)b.decoded, tc.want_decoded.len, (String)tc.want_decoded);

		assert(b.decoded == tc.want_decoded,
			"parser: failed to get decoded body: got: '%s', want: '%s'", (String)b.decoded, (String)tc.want_decoded);
	}
}

fn void test_multiple_pem_blocks() => @assert_leak()
{
	String stream = `
text before the block
-----BEGIN PEM-----

dGVzdA==
-----END PEM-----

some inbetween text

-----BEGIN PEM2-----

aGVsbG8gYWdhaW4K
-----END PEM2-----

text after the block`;

		ByteReader *reader = (ByteReader){}.init(stream);

		PemBlock b1 = pem::decode(reader)!!;
		defer b1.free();

		assert(b1.label == "PEM", "parser: failed to get label for first block");
		assert(b1.decoded == "test", "parser: failed to get decoded body for first block");

		PemBlock b2 = pem::decode(reader)!!;
		defer b2.free();

		assert(b2.label == "PEM2", "parser: failed to get label for second block");
		assert(b2.decoded == "hello again\n", "parser: failed to get decoded body for second block");
}
