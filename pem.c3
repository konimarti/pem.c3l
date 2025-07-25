module encoding::pem;

import encoding::pem::parser;
import encoding::pem::encoder;

import std::io;

fn PemBlock? decode(InStream input, Allocator allocator = mem)
{
	return (PemParser){}.init(input).next(allocator);
}
fn PemBlock? tdecode(InStream input) => decode(input, tmem);

fn String encode(String label, char[] data, Allocator allocator = mem)
{
	return encoder::encode(label, {}, data, allocator);
}
fn String tencode(String label, char[] data) => encode(label, data, tmem);

struct PemBlock
{
	String label;
	Headers headers;
	char[] decoded;
	Allocator allocator;
}

fn String PemBlock.encode(&self, Allocator allocator = mem)
{
	return encoder::encode(self.label, self.headers, self.decoded, allocator);
}
fn String PemBlock.tencode(&self) => self.encode(tmem);

fn void PemBlock.free(&self)
{
	if (!self.allocator) return;

	self.label.free(self.allocator);

	foreach (header : self.headers) header.free(self.allocator);
	self.headers.free();

	allocator::free(self.allocator, self.decoded);

	*self = {};
}
