module encoding::pem;

import encoding::pem::parser;
import std::io;

fn PemBlock? decode(InStream input, Allocator allocator = mem)
{
	return (PemParser){}.init(input).next(allocator);
}
fn PemBlock? tdecode(InStream input) => decode(input, tmem);

struct PemBlock
{
	String label;
	Headers headers;
	char[] decoded;
	Allocator allocator;
}

fn void PemBlock.free(&self)
{
	if (!self.allocator) return;

	self.label.free(self.allocator);

	foreach (header : self.headers) header.free(self.allocator);
	self.headers.free();

	allocator::free(self.allocator, self.decoded);

	*self = {};
}


