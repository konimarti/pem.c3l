module encoding::pem::parser;

import std::io;
import std::encoding::base64;

faultdef PEM_EMPTY_LABEL, PEM_LABEL_MISMATCH;

struct PemBlock
{
	String label;
	char[] decoded;
	Allocator allocator;
}

fn void PemBlock.free(&self)
{
	if (!self.allocator) return;
	allocator::free(self.allocator, self.label);
	allocator::free(self.allocator, self.decoded);
}

struct PemParser
{
	InStream reader;
}

fn PemParser* PemParser.init(&self, InStream reader)
{
	*self = { reader };
	return self;
}

// Read one line from the input stream into a temporary string
fn bool PemParser.readline(&self, DString *line)
{
	line.clear();
	while (true)
	{
		char? c = self.reader.read_byte();
		if (catch c) return line.len() > 0;

		if (c == '\n')
		{
			return true;
		}

		if (c != '\r')
		{
			line.append_char(c);
		}
	}
}

fn PemBlock? PemParser.next(&self, Allocator allocator = mem) => @pool()
{
	DString label      = dstring::temp();
	DString base64Data = dstring::temp();

	// find a BEGIN line
	while (try s = io::treadline(self.reader))
	{
		if (s.starts_with("-----BEGIN ") && s.ends_with("-----"))
		{
			label.append_chars(s[11 .. ^6]);
			break;
		}
	}

	if (label.len() == 0)
	{
		return PEM_EMPTY_LABEL?;
	}

	// parse headers (lines with ':') until empty line or base64 line
	while (try s = io::treadline(self.reader))
	{
		if (s.len == 0) break; // end of headers

		if (string::char_in_set(s[0], "\t "))
		{
			// continuation of previous header
			// @TODO: skipping headers for now
		}
		else if (try idx = s.index_of_char(':'))
		{
			// @TODO: skipping headers for now
		}
		else
		{
			base64Data.append_chars(s);
		}
	}

	// read until the END line
	while (try s = io::treadline(self.reader))
	{
		if (s.starts_with("-----END ") && s.ends_with("-----"))
		{
			DString endLabel = dstring::temp(s[9 .. ^6]);
			if (endLabel.str_view() != label.str_view())
			{
				// PEM block end label mismatch
				return PEM_LABEL_MISMATCH?;
			}
			break;
		}
		base64Data.append_chars(s);
	}

	char[] decoded = base64::decode(allocator, base64Data.str_view())!;

	return {
		label.str_view().copy(allocator),
		decoded,
		allocator
	};
}

module encoding::pem::parser @test;

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

fn void test_pem_block()
{
	PemParser p;
	p.init((ByteReader){}.init(PEM));

	PemBlock b = p.next()!!;
	defer b.free();

	String want_label = "PRIVACY-ENHANCED MESSAGE";
	assert(b.label == want_label, "parser: failed to get label: got: %s, want: %s", b.label, want_label);

	char[] want_decoded = "hello this is just a long line for base64 encoding, padding?\n";
	assert(b.decoded.len == want_decoded.len, "len does not match; got: %d, want: %d", b.decoded.len, want_decoded.len);
	assert(b.decoded == want_decoded, "parser: failed to get decoded body: got: '%s', want: '%s'", (String)b.decoded, (String)want_decoded);
}
