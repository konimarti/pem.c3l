module encoding::pem::encoder;

import encoding::pem::header;
import std::encoding::base64;

import std::io; // just for debugging

fn String encode(String label, Headers headers, char[] data, Allocator allocator) => @pool()
{
	DString writer = dstring::temp();

	// write BEGIN line
	writer.appendf("-----BEGIN %s-----\n", label);

	// write raw headers
	foreach (header : headers)
	{
		if (header.raw.len > 0)
		{
			io::printfn("writing %s", header.raw);
			writer.append_chars(header.raw);
		}
	}

	if (headers.len() > 0) writer.append_char('\n');

	// encode and wrap base64 body

	String base64str = base64::tencode(data);
	usz i = 0;
	while (i < base64str.len)
	{
		usz end = i + 64;
		if (end < base64str.len)
		{
			writer.append_chars(base64str[i .. end - 1]);
		}
		else
		{
			writer.append_chars(base64str[i .. ]);
		}
		writer.append_char('\n');
		i += 64;
	}

	// write END line
	writer.appendf("-----END %s-----\n", label);

	return writer.copy_str(allocator);
}


