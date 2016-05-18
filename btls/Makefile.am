BTLS_LIBS = build/libmono-btls-uninstalled.la
BTLS_CFLAGS = -I$(top_srcdir)/external/boringssl/include

BTLS_DEPS = $(BTLS_LIBS) build/Makefile

CMAKE_ARGS = -D CMAKE_INSTALL_PREFIX:PATH=$(prefix) -D BTLS_ROOT:PATH=$(BTLS_ROOT) -D SRC_DIR:PATH=$(srcdir)

build/Makefile:
	-mkdir -p build
	(cd build && $(CMAKE) $(CMAKE_ARGS) $(BTLS_CMAKE_ARGS) $(abs_top_srcdir)/btls)

$(BTLS_LIBS): build/Makefile
	$(MAKE) -C build
	
clean-local:
	-rm -rf build

install-exec-hook: $(BTLS_DEPS)
	$(MAKE) -C build install

noinst_PROGRAMS = martin-test

martin_test_SOURCES = \
	martin-test.c \
	martin-test.h
	
martin_test_CFLAGS = -I$(srcdir) $(BTLS_CFLAGS)
martin_test_LDADD = $(BTLS_LIBS)
martin_test_LDFLAGS = -all-static
