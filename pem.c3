module encoding::pem;

import std::collections::map;
import std::collections::list;
import std::encoding::base64;
import std::ascii;
import std::io;

// https://datatracker.ietf.org/doc/html/rfc1421

const String PEM_START = "\n-----BEGIN";
const String PEM_END = "\n-----END";
const String PEM_EOL = "-----";
const String COLON = ":";

alias Header = HashMap {String, String};

faultdef INVALID_PEM_LINE_END, PEM_TYPE_MISMATCH;

fn PemBlock? decode(String s, Allocator allocator)
{
	return (Parser){}.init(s).pem_block(allocator);
}

fn PemBlock? decode_new(String s) => decode(s, allocator::heap());
fn PemBlock? decode_temp(String s) => decode(s, allocator::temp());

struct PemBlock
{
	Allocator allocator;
	String type;
	Header header;
	char[] bytes;
}

fn PemBlock* PemBlock.init(&self, Allocator allocator)
{
	*self = { .allocator = allocator };
	return self;
}

fn usz? PemBlock.to_format(&self, Formatter *f) @dynamic
{
	usz n;
	n += f.printf("PEM block:\n")!;
	n += f.printf("----------\n")!;
	n += f.printf("%s\n", self.type)!;

	n += f.printf("\nHeader: \n")!;
	n += f.printf("-------\n")!;

	if (self.header.is_empty())
	{
		n += f.printf("No header.\n")!;
	}
	else
	{
		self.header.@each(; String k, String v)
		{
			n += f.printf("%s: %s\n", k, v)!;
		};
	}

	n += f.printf("\nBytes:\n")!;
	n += f.printf("------\n")!;

	bool is_print = true;
	foreach (c : self.bytes) is_print = ascii::is_print(c) && is_print;
	if (is_print)
	{
			n += f.printf("%s\n", self.bytes)!;
	}
	else
	{
		@pool() {
			n += f.printf("%s\n", base64::tencode(self.bytes))!;
		};
	}
	return n;
}

fn void PemBlock.free(&self)
{
	// String
	self.type.free(self.allocator);

	// Header
	self.header.@each(; String key, String value) { value.free(self.allocator); };
	self.header.free();

	// char[]
	allocator::free(self.allocator, self.bytes);
}

struct Parser
{
	String s;
	usz pos;
}

fn Parser* Parser.init(&self, String s)
{
	*self = {.s = s, .pos = 0};
	return self;
}

 // getline returns a string with the trailing \r and \n characters removed.
 // the parser position index is moved beyond the newline character.
fn String? Parser.getline(&p)
{
	if (p.pos >= p.s.len) return io::EOF?;

	usz start, end;
	usz? i;

	start = p.pos;
	i = p.s[start..].index_of_char('\n');
	if (catch err = i)
	{
		end = p.s.len;
		p.pos = end;
		return p.s[start..];
	}

	end = start + i;
	p.pos = end + 1; // p.pos points after \n
	if (end > start && p.s[end] == '\n') end--;
	if (end > start && p.s[end] == '\r') end--;

	// io::printfn("start: %d", start);
	// io::printfn("end:   %d", end);
	// io::printfn("pos:   %d", p.pos);
	// io::printfn("str:  '%s'", p.s[start..end]);

	if (start == end) return "";

	return p.s[start..end];
}

// moves to the next PEM begin line and reads the PEM type.
fn usz? Parser.pem_line(&p, String pem)
{
 	// -----BEGIN PRIVACY-ENHANCED MESSAGE-----[\r]\n
	//           ^

	usz start = p.pos;
	if (p.s[p.pos..].starts_with(pem[1..]))
	{
		p.pos += pem.len - 1;
	}
	else
	{
		start += p.s[p.pos..].index_of(pem)!;
		p.pos = start + pem.len;
	}
	return start;
}

fn String? Parser.pem_type(&p)
{
	String type_line = p.getline()!;
	if (!type_line.ends_with(PEM_EOL))
	{
		return INVALID_PEM_LINE_END?;
	}
	type_line = type_line[:^PEM_EOL.len];
	return type_line.trim();
}

<*
@param [&inout] header
*>
fn void? Parser.headers(&p, Header *header)
{
	// currently we read headers and discard them
	usz reset;
	String line;
	while LOOP: (1)
	{
		reset = p.pos;
		line = p.getline()!;
		if (!line.contains(":"))
		{
			p.pos = reset;
			break LOOP;
		}

		usz sep = line.index_of_char(':')!;
		String key = line[:sep].trim();
		// io::printfn("key   = %s", line[:sep]);

		List {String} values;
		values.tinit();
		values.push(line[sep+2..]);

		while (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
			while (p.pos < p.s.len && ascii::is_space(p.s[p.pos])) p.pos++;
			String cont_line = p.getline()!;
			values.push(cont_line);
		}

		String value = string::join(allocator::temp(), values.to_tarray(), "");

		// io::printfn("saving '%s': '%s'", key, value);
		header.set(key, value);
	}
}

fn PemBlock? Parser.pem_block(&p, Allocator allocator)
{
	p.pem_line(pem::PEM_START)!;
	String begin_type = p.pem_type()!;

	Header tmp_header;
	p.headers(tmp_header.tinit())!;

	usz start = p.pos;
	usz end = p.pem_line(pem::PEM_END)!;

	if (begin_type != p.pem_type()!) return PEM_TYPE_MISMATCH?;

	String enc = p.s[start..end].trim();

	char[] block = allocator::new_array(allocator::temp(), char, enc.len);

	usz i = 0;
	foreach (c : enc)
	{
		if (!ascii::is_space(c)) block[i++] = c;
	}

	PemBlock b;
	b.init(allocator);
	b.header.init(allocator);
	tmp_header.@each(; String key, String value)
	{
		// io::printfn("adding '%s': '%s'", key, value);
		b.header.set(key, value.copy(allocator));
	};
	b.type = begin_type.copy(allocator);
	b.bytes = base64::decode(allocator, block[:i])!;

	// io::printfn("block size: %d", i);
	// io::printfn("decode len: %d", dec.decode_len(i)!);
	// io::printfn("returned  : %d", n);

	return b;
}

