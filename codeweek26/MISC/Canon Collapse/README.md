# Canon Collapse
**ID:** 34
**Category:** MISC
**Points:** 500

## Description
Earth-42 relay traffic coughed up one image and a lot of bad telemetry. The
picture opens, the sensors complain, and the archive team says the byte stream
does not line up the way it should.

Some bytes are there for the picture;
some bytes are only there to get in the way. The obvious ZIP-looking traffic is
part of the interference, not proof that the stream is aligned.

The route was left where BMP parsers usually stop caring. The real stream rides
in the high-word lane and does not arrive in scanline order.

After that, the small integrity binary handles the rest. It has a real path and
a few bad ones; reverse it before submitting whatever looks convenient. The
archive password is not the society token.


Author:
zennova
