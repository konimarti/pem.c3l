module app;

import encoding::pem;
import std::io;

fn void main()
{
	String encoded = pem::encode("SOME PEM BLOCK", "hello world");

	io::printn("PEM block:");
	io::printn(encoded);
}
