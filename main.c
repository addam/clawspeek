/*
 * Claws Mail -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 2016 The Claws Mail Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _XOPEN_SOURCE 600
#include <unistd.h>
#include <stdlib.h>
#include <crypt.h>
#include <stdint.h>

# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>

#include <glib.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define PASSCRYPT_KEY "passkey0"

static char *_master_passphrase = NULL;
char *master_passphrase_salt = "WyoFwVxDLvZd5PnrtMaNgY2ZVx6/QK7nHN2e9n4CdBMV4jgi+toxvinWM3Pou5GmiQch6qMgsVyrHy6qa+CJuQ==";
char *global_master_passphrase = NULL;

/* Length of stored key derivation, before base64. */
#define KD_LENGTH 64

/* Length of randomly generated and saved salt, used for key derivation.
 * Also before base64. */
#define KD_SALT_LENGTH 64

static void crypt_cfb_buf(const char key[8], unsigned char *buf, unsigned len, unsigned chunksize, int decrypt);

void passcrypt_encrypt(char *password, guint len)
{
	crypt_cfb_buf(PASSCRYPT_KEY, password, len, 1, 0 );
}

void passcrypt_decrypt(char *password, guint len)
{
	crypt_cfb_buf(PASSCRYPT_KEY, password, len, 1, 1 );
}

/*
* crypt_cfb_iv is the intermediate vector used for cypher feedback encryption
*/
unsigned char crypt_cfb_iv[64];
int crypt_cfb_blocksize = 8;	/* 8 for DES */

static void crypt_cfb_shift(unsigned char *to,
			    const unsigned char *from, unsigned len);
static void crypt_cfb_xor(unsigned char *to, const unsigned char *from,
			  unsigned len);
static void crypt_unpack(unsigned char *a);

static void
crypt_cfb_buf(const char key[8], unsigned char *buf, unsigned len,
	      unsigned chunksize, int decrypt)
{
	unsigned char temp[64];

	memcpy(temp, key, 8);
	crypt_unpack(temp);
	setkey((const char *) temp);
	memset(temp, 0, sizeof(temp));

	memset(crypt_cfb_iv, 0, sizeof(crypt_cfb_iv));

	if (chunksize > crypt_cfb_blocksize)
		chunksize = crypt_cfb_blocksize;

	while (len) {
		memcpy(temp, crypt_cfb_iv, sizeof(temp));
		encrypt((char *) temp, 0);
		if (chunksize > len)
			chunksize = len;
		if (decrypt)
			crypt_cfb_shift(crypt_cfb_iv, buf, chunksize);
		crypt_cfb_xor((unsigned char *) buf, temp, chunksize);
		if (!decrypt)
			crypt_cfb_shift(crypt_cfb_iv, buf, chunksize);
		len -= chunksize;
		buf += chunksize;
	}
}

/*
* Shift len bytes from end of to buffer to beginning, then put len
* bytes from from at the end.  Caution: the to buffer is unpacked,
* but the from buffer is not.
*/
static void
crypt_cfb_shift(unsigned char *to, const unsigned char *from, unsigned len)
{
	unsigned i;
	unsigned j;
	unsigned k;

	if (len < crypt_cfb_blocksize) {
		i = len * 8;
		j = crypt_cfb_blocksize * 8;
		for (k = i; k < j; k++) {
			to[0] = to[i];
			++to;
		}
	}

	for (i = 0; i < len; i++) {
		j = *from++;
		for (k = 0x80; k; k >>= 1)
			*to++ = ((j & k) != 0);
	}
}

/*
* XOR len bytes from from into the data at to.  Caution: the from buffer
* is unpacked, but the to buffer is not.
*/
static void
crypt_cfb_xor(unsigned char *to, const unsigned char *from, unsigned len)
{
	unsigned i;
	unsigned j;
	unsigned char c;

	for (i = 0; i < len; i++) {
		c = 0;
		for (j = 0; j < 8; j++)
			c = (c << 1) | *from++;
		*to++ ^= c;
	}
}

/*
* Take the 8-byte array at *a (must be able to hold 64 bytes!) and unpack
* each bit into its own byte.
*/
static void crypt_unpack(unsigned char *a)
{
	int i, j;

	for (i = 7; i >= 0; --i)
		for (j = 7; j >= 0; --j)
			a[(i << 3) + j] = (a[i] & (0x80 >> j)) != 0;
}


#define CHECKSUM_BLOCKLEN 64
/*
 * HMAC-SHA-1 (from RFC 2202).
 */
static void
hmac_sha1(const guchar *text, size_t text_len, const guchar *key,
    size_t key_len, guchar *digest)
{
	GChecksum *cksum;
	gssize digestlen = g_checksum_type_get_length(G_CHECKSUM_SHA1);
	gsize outlen;
	guchar k_pad[CHECKSUM_BLOCKLEN];
	guchar tk[digestlen];
	int i;

	if (key_len > CHECKSUM_BLOCKLEN) {
		cksum = g_checksum_new(G_CHECKSUM_SHA1);
		g_checksum_update(cksum, key, key_len);
		outlen = digestlen;
		g_checksum_get_digest(cksum, tk, &outlen);
		g_checksum_free(cksum);

		key = tk;
		key_len = digestlen;
	}

	memset(k_pad, 0, sizeof k_pad);
	memcpy(k_pad, key, key_len);
	for (i = 0; i < CHECKSUM_BLOCKLEN; i++)
		k_pad[i] ^= 0x36;

	cksum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(cksum, k_pad, CHECKSUM_BLOCKLEN);
	g_checksum_update(cksum, text, text_len);
	outlen = digestlen;
	g_checksum_get_digest(cksum, digest, &outlen);
	g_checksum_free(cksum);

	memset(k_pad, 0, sizeof k_pad);
	memcpy(k_pad, key, key_len);
	for (i = 0; i < CHECKSUM_BLOCKLEN; i++)
		k_pad[i] ^= 0x5c;

	cksum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(cksum, k_pad, CHECKSUM_BLOCKLEN);
	g_checksum_update(cksum, digest, digestlen);
	outlen = digestlen;
	g_checksum_get_digest(cksum, digest, &outlen);
	g_checksum_free(cksum);
}

#undef CHECKSUM_BLOCKLEN

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 */
int
pkcs5_pbkdf2(const gchar *pass, size_t pass_len, const guchar *salt,
    size_t salt_len, guchar *key, size_t key_len, guint rounds)
{
	gssize digestlen = g_checksum_type_get_length(G_CHECKSUM_SHA1);
	guchar *asalt, obuf[digestlen];
	guchar d1[digestlen], d2[digestlen];
	guint i, j;
	guint count;
	size_t r;

	if (rounds < 1 || key_len == 0)
		return -1;
	if (salt_len == 0 || salt_len > SIZE_MAX - 4)
		return -1;
	if ((asalt = malloc(salt_len + 4)) == NULL)
		return -1;

	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1);
		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			hmac_sha1(d1, sizeof(d1), pass, pass_len, d2);
			memcpy(d1, d2, sizeof(d1));
			for (j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		r = MIN(key_len, digestlen);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};
	memset(asalt, 0, salt_len + 4);
	free(asalt);
	memset(d1, 0, sizeof(d1));
	memset(d2, 0, sizeof(d2));
	memset(obuf, 0, sizeof(obuf));

	return 0;
}

/* Attempts to read count bytes from a PRNG into memory area starting at buf.
 * It is up to the caller to make sure there is at least count bytes
 * available at buf. */
int
get_random_bytes(void *buf, size_t count)
{
	/* Open our prng source. */
#if defined G_OS_WIN32
	HCRYPTPROV rnd;

	if (!CryptAcquireContext(&rnd, NULL, NULL, PROV_RSA_FULL, 0) &&
			!CryptAcquireContext(&rnd, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		debug_print("Could not acquire a CSP handle.\n");
		return FALSE;
	}
#else
	int rnd;
	ssize_t ret;

	rnd = open("/dev/urandom", O_RDONLY);
	if (rnd == -1) {
		fprintf(stderr, "Could not open /dev/urandom.\n");
		return FALSE;
	}
#endif

	/* Read data from the source into buf. */
#if defined G_OS_WIN32
	if (!CryptGenRandom(rnd, count, buf)) {
		debug_print("Could not read %zd random bytes.\n", count);
		CryptReleaseContext(rnd, 0);
		return FALSE;
	}
#else
	ret = read(rnd, buf, count);
	if (ret != count) {
		fprintf(stderr, "Could not read enough data from /dev/urandom, read only %ld of %lu bytes.\n", ret, count);
		close(rnd);
		return FALSE;
	}
#endif

	/* Close the prng source. */
#if defined G_OS_WIN32
	CryptReleaseContext(rnd, 0);
#else
	close(rnd);
#endif

	return TRUE;
}


static void _generate_salt()
{
	guchar salt[KD_SALT_LENGTH];

	if (master_passphrase_salt != NULL) {
		g_free(master_passphrase_salt);
	}

	if (!get_random_bytes(salt, KD_SALT_LENGTH)) {
		printf("Could not get random bytes for kd salt.\n");
		return;
	}

	master_passphrase_salt =
		g_base64_encode(salt, KD_SALT_LENGTH);
}

#undef KD_SALT_LENGTH

static guchar *_make_key_deriv(const char *passphrase, guint rounds,
		guint length)
{
	guchar *kd, *salt;
	char *saltpref = master_passphrase_salt;
	gsize saltlen;
	int ret;

	/* Grab our salt, generating and saving a new random one if needed. */
	if (saltpref == NULL || strlen(saltpref) == 0) {
		_generate_salt();
		saltpref = master_passphrase_salt;
	}
	salt = g_base64_decode(saltpref, &saltlen);
	kd = g_malloc0(length);

	ret = pkcs5_pbkdf2(passphrase, strlen(passphrase), salt, saltlen,
			kd, length, rounds);

	g_free(salt);

	if (ret == 0) {
		return kd;
	}

	g_free(kd);
	return NULL;
}

static const char *master_passphrase()
{
	char *input;
	int end = FALSE;

	return PASSCRYPT_KEY;
#if 0
	if (_master_passphrase != NULL) {
		printf("Master passphrase is in memory, offering it.\n");
		return _master_passphrase;
	}

	while (!end) {
		input = input_dialog_with_invisible(_("Input master passphrase"),
				_("Input master passphrase"), NULL);

		if (input == NULL) {
			printf("Cancel pressed at master passphrase dialog.\n");
			break;
		}

		if (master_passphrase_is_correct(input)) {
			printf("Entered master passphrase seems to be correct, remembering it.\n");
			_master_passphrase = input;
			end = TRUE;
		} else {
			alertpanel_error(_("Incorrect master passphrase."));
		}
	}

	return _master_passphrase;
#endif
}

const int master_passphrase_is_set()
{
	if (global_master_passphrase == NULL
			|| strlen(global_master_passphrase) == 0)
		return FALSE;

	return TRUE;
}

const int master_passphrase_is_correct(const char *input)
{
	guchar *kd, *input_kd;
	char **tokens;
	char *stored_kd = global_master_passphrase;
	gsize kd_len;
	guint rounds = 0;
	int ret;

	g_return_val_if_fail(stored_kd != NULL && strlen(stored_kd) > 0, FALSE);
	g_return_val_if_fail(input != NULL, FALSE);

	if (stored_kd == NULL)
		return FALSE;

	tokens = g_strsplit_set(stored_kd, "{}", 3);
	if (tokens[0] == NULL ||
			strlen(tokens[0]) != 0 || /* nothing before { */
			tokens[1] == NULL ||
			strncmp(tokens[1], "PBKDF2-HMAC-SHA1,", 17) || /* correct tag */
			strlen(tokens[1]) <= 17 || /* something after , */
			(rounds = atoi(tokens[1] + 17)) <= 0 || /* valid rounds # */
			tokens[2] == NULL ||
			strlen(tokens[2]) == 0) { /* string continues after } */
		printf("Mangled master_passphrase format in config, can not use it.\n");
		g_strfreev(tokens);
		return FALSE;
	}

	stored_kd = tokens[2];
	kd = g_base64_decode(stored_kd, &kd_len); /* should be 64 */
	g_strfreev(tokens);

	if (kd_len != KD_LENGTH) {
		printf("master_passphrase is %ld bytes long, should be %d.\n",
				kd_len, KD_LENGTH);
		g_free(kd);
		return FALSE;
	}

	input_kd = _make_key_deriv(input, rounds, KD_LENGTH);
	ret = memcmp(kd, input_kd, kd_len);

	g_free(input_kd);
	g_free(kd);

	if (ret == 0)
		return TRUE;

	return FALSE;
}

int master_passphrase_is_entered()
{
	return (_master_passphrase == NULL) ? FALSE : TRUE;
}

void master_passphrase_forget()
{
	/* If master passphrase is currently in memory (entered by user),
	 * get rid of it. User will have to enter the new one again. */
	if (_master_passphrase != NULL) {
		memset(_master_passphrase, 0, strlen(_master_passphrase));
		g_free(_master_passphrase);
		_master_passphrase = NULL;
	}
}

char *password_decrypt_old(const char *password)
{
	if (!password || strlen(password) == 0) {
		return NULL;
	}

	if (*password != '!' || strlen(password) < 2) {
		return NULL;
	}

	gsize len;
	char *decrypted = g_base64_decode(password + 1, &len);

	passcrypt_decrypt(decrypted, len);
	return decrypted;
}

#define BUFSIZE 128

/* Since we can't count on having GnuTLS new enough to have
 * gnutls_cipher_get_iv_size(), we hardcode the IV length for now. */
#define IVLEN 16

char *password_decrypt_gnutls(const char *password,
		const char *decryption_passphrase)
{
	char **tokens, *tmp;
	gnutls_cipher_algorithm_t algo;
	gnutls_cipher_hd_t handle;
	gnutls_datum_t key, iv;
	int keylen, blocklen, ret;
	gsize len;
	unsigned char *buf;
	guint rounds;
	size_t commapos;

	g_return_val_if_fail(password != NULL, NULL);
	g_return_val_if_fail(decryption_passphrase != NULL, NULL);

	tokens = g_strsplit_set(password, "{}", 3);

	/* Parse the string, retrieving algorithm and encrypted data.
	 * We expect "{algorithm,rounds}base64encodedciphertext". */
	if (tokens[0] == NULL || strlen(tokens[0]) != 0 ||
			tokens[1] == NULL || strlen(tokens[1]) == 0 ||
			tokens[2] == NULL || strlen(tokens[2]) == 0) {
		printf("Garbled password string.\n");
		g_strfreev(tokens);
		return NULL;
	}

	commapos = strcspn(tokens[1], ",");
	if (commapos == strlen(tokens[1]) || commapos == 0) {
		printf("Garbled algorithm substring.\n");
		g_strfreev(tokens);
		return NULL;
	}

	buf = g_strndup(tokens[1], commapos);
	if ((algo = gnutls_cipher_get_id(buf)) == GNUTLS_CIPHER_UNKNOWN) {
		printf("Password string has unknown algorithm: '%s'\n", buf);
		g_free(buf);
		g_strfreev(tokens);
		return NULL;
	}
	g_free(buf);

	if ((rounds = atoi(tokens[1] + commapos + 1)) <= 0) {
		printf("Invalid number of rounds: %d\n", rounds);
		g_strfreev(tokens);
		return NULL;
	}

/*	ivlen = gnutls_cipher_get_iv_size(algo); */
	keylen = gnutls_cipher_get_key_size(algo);
	blocklen = gnutls_cipher_get_block_size(algo);
/*	digestlen = gnutls_hash_get_len(digest); */

	/* Take the passphrase and compute a key derivation of suitable
	 * length to be used as encryption key for our block cipher. */
	key.data = _make_key_deriv(decryption_passphrase, rounds, keylen);
	key.size = keylen;

	/* Prepare random IV for cipher */
	iv.data = malloc(IVLEN);
	iv.size = IVLEN;
	if (!get_random_bytes(iv.data, IVLEN)) {
		g_free(key.data);
		g_free(iv.data);
		g_strfreev(tokens);
		return NULL;
	}

	/* Prepare encrypted password string for decryption. */
	tmp = g_base64_decode(tokens[2], &len);
	g_strfreev(tokens);
	if (tmp == NULL || len == 0) {
		printf("Failed base64-decoding of stored password string\n");
		g_free(key.data);
		g_free(iv.data);
		if (tmp != NULL)
			g_free(tmp);
		return NULL;
	}

	/* Initialize the decryption */
	ret = gnutls_cipher_init(&handle, algo, &key, &iv);
	if (ret < 0) {
		printf("Cipher init failed: %s\n", gnutls_strerror(ret));
		g_free(key.data);
		g_free(iv.data);
		g_free(tmp);
		return NULL;
	}

	buf = malloc(len + blocklen);
	memset(buf, 0, len + blocklen);
	ret = gnutls_cipher_decrypt2(handle, tmp, len,
			buf, len + blocklen);
	g_free(tmp);
	if (ret < 0) {
		printf("Decryption failed: %s\n", gnutls_strerror(ret));
		g_free(key.data);
		g_free(iv.data);
		g_free(buf);
		gnutls_cipher_deinit(handle);
		return NULL;
	}

	/* Cleanup */
	gnutls_cipher_deinit(handle);
	g_free(key.data);
	g_free(iv.data);

	tmp = g_strndup(buf + blocklen, MIN(strlen(buf + blocklen), BUFSIZE));
	g_free(buf);
	return tmp;
}

char *password_decrypt(const char *password, const char *decryption_passphrase)
{
	if (password == NULL || strlen(password) == 0) {
		return NULL;
	}

	/* First, check if the password was possibly decrypted using old,
	 * obsolete method */
	if (*password == '!') {
		printf("Old-style password:\n");
		return password_decrypt_old(password);
	}

	/* Try available crypto backend */
	if (decryption_passphrase == NULL)
		decryption_passphrase = master_passphrase();

	if (*password == '{') {
		printf("New-style password:\n");
		return password_decrypt_gnutls(password, decryption_passphrase);
	}

	/* Fallback, in case the configuration is really old and
	 * stored password in plaintext */
	printf("Unable to decrypt:\n");
	return g_strdup(password);
}

int main(int argc, char **argv)
{
	if (argc > 2) {
		master_passphrase_salt = argv[1];
		for (int i=2; i < argc; ++i) {
			char *pass = password_decrypt(argv[i], NULL);
			printf("%s\n", pass);
		}
	}
	return 0;
}
