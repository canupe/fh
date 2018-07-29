FH (file hider) readme
0) Intro
FH is a privacy tool base on the contrary of the security by obscurity principle.  
I think that something is secure if ti secure, not relying on the fact that it is secret, because sooner or later it will be not secret anymore.
So everyone is invited to comment and give suggestions on how to make it better.

FH is a privacy tool that can:
- encrypt and decrypt files with three different algorithms
- format the final result in three different modes
- decrypt

1) Encryption phase
Encryption is the default, anyway mode is governed by the -m flag (m=E is encrypt)
1.1) Algorithms  
Three algorithms can be used
	- AES with 256 bit key and 128 bit block size
	- TWOFISH with 256 bit key and 128 bit block size
	- THREEFISH with 1024 bit key and 1024 bit block size
	  THREEFISH mode also has a TWEAK of 128 bit
(Mode is always CBC with an IV which has the size of the block key)
The algorithm is controlled with the -a flag (0=AES 1=TWOFISH 2=THREEFISH), default is 0
IV and tweak will be random generated and stored in the so-called 'microheader' (see later)

1.2) Password  
The password provided as text is always 'salted' according to PBKDF2 with sha512 HMAC
The password is given with the -p flag and the salt is stored in the 'microheader'

1.3) Input files  
Input may be a single file or a group of files. Use -i to select files

1.4) Compression  
To avoid known plaintext attack and to increment efficiency, the file(s) to be 
protected anymoreput into a gz archive. A good side effect of this is that attack
the end of decryption their name can be retrieved. Compression is mandatory

1.5) Output file phase 1  
The compressed payload is encrypted and then formatted in 3 possibile ways
	- RAW
		- encrypted data is prepended with the microheader in clear
	- Monocolor 8bpp BMP image
		- microheader and encrypted data are preprended with a 8bpp BMP header
		  with a color table mapping all 256 colors on the same one.
		  The result will be a perfecly legal monocolor image
	- Multicolor 32bpp BMP image
		- As above but with 32bit per pixel with no color table. The result will
		  be a perfectly legal 'white noise' image
The phase 1 output is governed by -f flag (R=RAW 1=8bpp mono 4=32bpp multi)  
Default is 1  
 
1.6) Output file phase 2  
- If no modifier is given, the Phase 1 file is the final result
- If -e=xxxx.bmp is given, Phase 1 result is postponed to the regular xxxx.bmp
  given, which must be a BMP whose length in header matches the file length.
  Since software open BMP 'from the start' the occasional observer will see
  just the 'prepended' fake BMP.
- If -eb=xxxx.bmp Phase 1 result is 'merged' into the provided BMP, which must
  be a 24bpp image of standard 'type 40' and no color table. The merging is done
  'stealing' the last two bits of each R-G-B byte representation. Remember that 
  'stealing' takes 2 bits each 8 so the hosting image must be more than 4 times
  the size of the phase 1 output. If not, simple prepending is done

IF mode 'RAW' is used and -eb= is used with a not too flat-coloured image, 
it will be very hard if not impossibile to demonstrate that the result is not a
regular image.  

1.7) Final output name  
Use -o to decide the final name of the result. If omitted, the first (or only)
input file, with suffix '.out' will be used.

2) Decryption phase (-m=D)  

2.1) Algorithm and format  
Algorithm and format and prepended/merged bmp are automatically detected and
managed by the decryption phase
2.2) Password  
Use -p to provide the password


3) Examples  

fh -p=SeCrEt! -i="cryptthis.doc"  
	Encrypt cryptthis.doc into cryptthis.out with algo=0 and format = 1  
	(rename as BMP and open to check)
fh -p=SeCrEt! -i="cryptthis.doc"  -o="output.bmp"  
	As above, with predefined ouput name  
fh -p=SeCrEt! -i="cryptthis.doc"  -a=2 -f=R  
	As above, choosing algo and format  
fh -p=SeCrEt! -i="cryptthis.doc" -f=R -e=guest.bmp  
	guest.bmp will be prepended  
fh -p=SeCrEt! -i="cryptthis.doc" -f=R -eb=guest.bmp  
	guest.bmp will be used as guest image  
