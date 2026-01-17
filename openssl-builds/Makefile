VERSIONS = 0.9.8zh 1.0.2u 1.1.1w 3.0.14
PREFIX_BASE = $(CURDIR)/build

all: $(VERSIONS)

0.9.8zh:
	wget -c https://www.openssl.org/source/old/0.9.x/openssl-0.9.8zh.tar.gz
	tar -xzf openssl-0.9.8zh.tar.gz
	cd openssl-0.9.8zh && ./config --prefix=$(PREFIX_BASE)/openssl-0.9.8zh
	#cd openssl-0.9.8zh && make -j && make install_sw
	cd openssl-0.9.8zh && make && make install_sw

1.0.2u:
	wget -c https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz
	tar -xzf openssl-1.0.2u.tar.gz
	cd openssl-1.0.2u && ./config \
		enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers \
  		enable-ec enable-ec2m enable-gost enable-camellia enable-seed enable-rfc3779 \
  		enable-md2 enable-md4 enable-rc2 enable-rc4 enable-idea enable-des enable-ripemd \
  		enable-nextprotoneg enable-srp enable-psk enable-engine enable-cms enable-null \
		--prefix=$(PREFIX_BASE)/openssl-1.0.2u
	#cd openssl-1.0.2u && make -j && make install_sw
	cd openssl-1.0.2u && make && make install_sw

1.1.1w:
	wget -c https://www.openssl.org/source/openssl-1.1.1w.tar.gz
	tar -xzf openssl-1.1.1w.tar.gz
	cd openssl-1.1.1w && \
		export LDFLAGS="-Wl,-rpath=$(PREFIX_BASE)/openssl-1.1.1w/lib" && \
		./config \
			enable-ssl3 enable-weak-ssl-ciphers enable-ec \
  			enable-gost enable-camellia enable-seed enable-md2 enable-md4 enable-rc2 enable-rc4 \
  			enable-idea enable-des enable-ripemd enable-nextprotoneg enable-srp enable-psk \
  			enable-cms enable-comp enable-ct enable-zlib \
			--prefix=$(PREFIX_BASE)/openssl-1.1.1w
	#cd openssl-1.1.1w && make -j && make install_siw
	cd openssl-1.1.1w && make && make install_sw

3.0.14:
	wget -c https://www.openssl.org/source/openssl-3.0.14.tar.gz
	tar -xzf openssl-3.0.14.tar.gz
	cd openssl-3.0.14 && ./Configure linux-aarch64 \
		enable-legacy enable-weak-ssl-ciphers enable-ssl3 enable-ssl3-method enable-zlib enable-zlib-dynamic \
  		enable-ec enable-gost enable-camellia enable-seed enable-md2 enable-md4 enable-rc2 enable-rc4 \
  		enable-idea enable-des enable-ripemd enable-nextprotoneg enable-srp enable-psk \
  		enable-cms enable-comp enable-ct enable-aria  \
		--prefix=$(PREFIX_BASE)/openssl-3.0.14 \
		--openssldir=$(PREFIX_BASE)/openssl-3.0.14/ssl
	cd openssl-3.0.14 && make -j && make install_sw

clean:
	rm -rf openssl-* build

