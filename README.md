# DMG2IMG

DMG2IMG is a tool which allows converting Apple compressed dmg
archives to standard (hfsplus) image disk files.

This tool handles zlib, bzip2, and LZFSE compressed dmg images.


Usage:

    dmg2img [-l] [-p N] [-s] [-v] [-V] [-d] <input.dmg> [<output.img> | -]

or

    dmg2img [-l] [-p N] [-s] [-v] [-V] [-d] -i <input.dmg> -o <output.img | ->

    Options: -s (silent) -v (verbose) -V (extremely verbose) -d (debug)
             -l (list partitions) -p N (extract only partition N)


See the original [README](README) file for platform-specific instructions to
open or mount the resulting output file.

The original author is vu1tur, <http://vu1tur.eu.org/dmg2img>. This Git
repository is maintained by Peter Wu at <https://github.com/Lekensteyn/dmg2img>
based on imported tarballs. It includes bug and security fixes and further
enhancements.

## Building

Required packages:

 - zlib1g-dev (zlib support)
 - libbz2-dev (bzip2 support)
 - libssl-dev (only required for vfdecrypt, not needed for dmg2img)

LZFSE decompression support requires the LZFSE library which can be found at
<https://github.com/lzfse/lzfse/>. As this library is not widely available on
Linux distributions, it is not enabled by default.

To build dmg2img:

    make dmg2img

To build dmg2img with LZFSE support:

    make dmg2img HAVE_LZFSE=1

To build dmg2img with Address Sanitizer for debugging purposes:

    make dmg2img CC=clang LDFLAGS=-fsanitize=address
