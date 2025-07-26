module encoding::pem::decoder;

import encoding::pem::parser;
import std::io;

fn PemBlock? decode(InStream input, Allocator allocator) @inline
{
	return (PemParser){}.init(input).next(allocator);
}

module encoding::pem::parser;

import encoding::pem::header;

import std::io;
import std::encoding::base64;

faultdef PEM_EMPTY_LABEL, PEM_LABEL_MISMATCH, PEM_CONTINUATION_WITHOUT_HEADER;

struct PemParser
{
	InStream reader;
}

fn PemParser* PemParser.init(&self, InStream reader)
{
	*self = { reader };
	return self;
}

fn PemBlock? PemParser.next(&self, Allocator allocator = mem) => @pool()
{
	DString label      = dstring::temp();
	DString base64Data = dstring::temp();
	DString lastKey    = dstring::temp();
	DString lastValue  = dstring::temp();
	DString rawHeader  = dstring::temp();

	Headers headers;
	headers.tinit();

	// find a BEGIN line
	while (try line = io::treadline(self.reader))
	{
		if (line.starts_with("-----BEGIN ") && line.ends_with("-----"))
		{
			label.append_chars(line[11 .. ^6]);
			break;
		}
	}
	if (label.len() == 0) return PEM_EMPTY_LABEL?;

	// parse headers (lines with ':') until empty line or base64 line
	while (try line = io::treadline(self.reader))
	{
		if (line.len > 0 && string::char_in_set(line[0], "\t "))
		{
			// continuation of previous header
			if (lastKey.len() == 0)
			{
				return PEM_CONTINUATION_WITHOUT_HEADER?;
			}
			lastValue.append_chars(line[1 .. ]);
			rawHeader.append_chars(line);
			rawHeader.append_char('\n');
		}
		else if (try idx = line.index_of_char(':'))
		{
			// new header - store previous if any
			if (lastKey.len() > 0)
			{
				headers.push({lastKey.tcopy_str(), lastValue.tcopy_str(), rawHeader.tcopy_str()});
			}

			lastKey.clear();
			lastValue.clear();
			lastKey.append_chars(line[0 .. idx - 1]);
			lastValue.append_chars(line[idx + 1 .. ].trim());

			rawHeader.clear();
			rawHeader.append_chars(line);
			rawHeader.append_char('\n');
		}
		else
		{
			// assume base64 line
			if (lastKey.len() > 0)
			{
				headers.push({lastKey.tcopy_str(), lastValue.tcopy_str(), rawHeader.tcopy_str()});
			}

			base64Data.append_chars(line);
			break;
		}
	}

	// read until the END line
	while (try line = io::treadline(self.reader))
	{
		if (line.starts_with("-----END ") && line.ends_with("-----"))
		{
			DString endLabel = dstring::temp(line[9 .. ^6]);
			if (endLabel.str_view() != label.str_view())
			{
				// PEM block end label mismatch
				return PEM_LABEL_MISMATCH?;
			}
			break;
		}
		base64Data.append_chars(line);
	}

	// decoded base64-encoded body
	char[] decoded = base64::decode(allocator, base64Data.str_view())!;

	// create copy of headers
	Headers header_copy;
	header_copy.init(allocator, 0);
	foreach (header : headers) header_copy.push(header.copy(allocator));

	return {
		label.str_view().copy(allocator),
		header_copy,
		decoded,
		allocator
	};
}
