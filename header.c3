module encoding::pem::header;

import std::collections::list;

struct HeaderEntry
{
	String key;
	String value;
}

fn HeaderEntry HeaderEntry.copy(&self, Allocator allocator)
{
	return { self.key.copy(allocator), self.value.copy(allocator) };
}

fn void HeaderEntry.free(&self, Allocator allocator)
{
	if (!allocator) return;
	self.key.free(allocator);
	self.value.free(allocator);
}

alias Headers = List{HeaderEntry};

