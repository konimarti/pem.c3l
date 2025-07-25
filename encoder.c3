module encoding::pem::encoder;

import std::encoding::base64;

fn String encode(String label, char[] data, Allocator allocator) => @pool()
{
	DString writer = dstring::temp();

	// write BEGIN line
	writer.appendf("-----BEGIN %s-----\n", label);

	// @TODO: write headers

	// encode and wrap base64 body

	String base64str = base64::tencode(data);
	usz i = 0;
	while (i < base64str.len)
	{
		usz end = i + 64;
		if (end < base64str.len)
		{
			writer.append_chars(base64str[i .. end]);
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


