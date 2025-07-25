module app;

import encoding::pem;
import std::io;
import std::math;

fn void main()
{
	String encoded = pem::encode("SOME PEM BLOCK", math::iota(char[128])[..]);

	io::printn("PEM block:");
	io::printn(encoded);
}
