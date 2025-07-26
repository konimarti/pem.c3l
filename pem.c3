module encoding::pem;

import encoding::pem::decoder;
import encoding::pem::encoder;

import std::io;

fn PemBlock? decode(InStream input, Allocator allocator = mem) @inline
{
	return decoder::decode(input, allocator);
}
fn PemBlock? tdecode(InStream input) @inline => decode(input, tmem);

fn String encode(String label, char[] data, Allocator allocator = mem) @inline
{
	return encoder::encode(label, {}, data, allocator);
}
fn String tencode(String label, char[] data) @inline => encode(label, data, tmem);

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
