APP=./a.out

default_target: ${APP}

${APP}: a.c
	cc a.c

clean:
	rm -f "${APP}"

define cmp_hashes
	@[ "${ACTUAL}" = "${EXPECT}" ] \
		&& echo "\e[1;32mPASS\e[0m\n" \
		|| echo "\e[1;31mFAIL\e[0m\nACTUAL=\"${ACTUAL}\"\n"
endef

define test
	$(eval INPUT=${1})
	$(eval EXPECT=${2})
	$(eval ACTUAL=$(shell echo -n "${INPUT}" | ./${APP} 2>/dev/null))
	$(call cmp_hashes)
endef

tests: ${APP} test-nist-b1 test-nist-b2 test-nist-b3 \
test-pad-1 test-pad-2 test-pad-3 test-pad-4

test-nist-b1: ${APP}
	# NIST.FIPS.180-2  B.1 SHA-256 Example (One-Block Message)
	$(call test,\
	  abc,\
	  ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad,\
	)

test-nist-b2: ${APP}
	# NIST.FIPS.180-2  B.2 SHA-256 Example (Multi-Block Message)
	$(call test,\
	  abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq,\
	  248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1,\
	)

test-nist-b3: ${APP}
	# NIST.FIPS.180-2  B.3 SHA-256 Example (Long Message)
	$(eval ACTUAL=$(shell for I in `seq 1 1000000`;do echo -n a;done\
	  | ./${APP} 2>/dev/null))
	$(eval EXPECT=\
	  cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0)
	$(call cmp_hashes)

test-pad-1: ${APP}
	# Compare with coreutils. Test padding.
	# '\x80' and size in first block
	$(call test,\
	  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012,\
	  59521aa5 a72bfd08 7fc7b180 efff1e20 dc27a7d6 232cc1eb b733183d 02a8c062,\
	)

test-pad-2: ${APP}
	# Compare with coreutils. Test padding.
	# '\x80' then zeros in first block, size in second
	$(call test,\
	  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123,\
	  f50e7755 9fcfb0be 5b298f78 0857cf0c 5f06af72 5838431f 7c9da48f f024ba30,\
	)

test-pad-3: ${APP}
	# Compare with coreutils. Test padding.
	# '\x80' in the end of first block, size in second
	$(call test,\
	  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-,\
	  1b725c00 691a61df 86f3f8aa ecc79ab9 ae37a5e2 078beb2a c3f0665e 9f0bdc11,\
	)

test-pad-4: ${APP}
	# Compare with coreutils. Test padding.
	# '\x80' in the begining of second block, size in second
	$(call test,\
	  ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=,\
	  54ea9bee 2a98b566 9bfc6fca 5cebffa4 c45f54a6 ec41e46b 14f39c5b 4b20a150,\
	)
