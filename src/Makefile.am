bin_PROGRAMS = passphrase-identity

passphrase_identity_CFLAGS = @PASSPHRASE_IDENTITY_CFLAGS@ @SODIUM_CFLAGS@
passphrase_identity_LDFLAGS = @SODIUM_LIBS@

passphrase_identity_SOURCES = \
	main.c \
	buffer.c buffer.h \
	buffer_writer.c  buffer_writer.h \
	memory.c memory.h \
	openssh.c openssh.h \
	sha1.c sha.h sha-private.h \
	openpgp.c openpgp.h \
	profile.c profile.h \
	readpassphrase.c readpassphrase.h
