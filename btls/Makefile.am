BTLS_STATIC_LIBS = build-static/libmono-btls-static.a
BTLS_SHARED_LIBS = build-shared/libmono-btls-shared.la
BTLS_LIBS = $(BTLS_STATIC_LIBS) $(BTLS_SHARED_LIBS)
BTLS_CFLAGS = -I$(top_srcdir)/external/boringssl/include

BTLS_DEPS = $(BTLS_LIBS) build-shared/Makefile build-static/Makefile

CMAKE_ARGS = -D CMAKE_INSTALL_PREFIX:PATH=$(prefix) -D BTLS_ROOT:PATH=$(BTLS_ROOT) -D SRC_DIR:PATH=$(srcdir)

all-local: $(BTLS_LIBS)

build-shared/Makefile:
	-mkdir -p build-shared
	(cd build-shared && $(CMAKE) $(CMAKE_ARGS) $(BTLS_CMAKE_ARGS) -DBUILD_SHARED_LIBS=1 $(abs_top_srcdir)/btls)

build-static/Makefile:
	-mkdir -p build-static
	(cd build-static && $(CMAKE) $(CMAKE_ARGS) $(BTLS_CMAKE_ARGS) $(abs_top_srcdir)/btls)

$(BTLS_STATIC_LIBS): build-static/Makefile
	$(MAKE) -C build-static
	
$(BTLS_SHARED_LIBS): build-shared/Makefile
	$(MAKE) -C build-shared
	
clean-local:
	-rm -rf build-static
	-rm -rf build-shared

#install-exec-hook: $(BTLS_DEPS)
#	$(MAKE) -C build-static install
#	$(MAKE) -C build-shared install

if CROSS_COMPILE
martin_test_programs =
else
martin_test_programs = martin-test
endif

noinst_PROGRAMS = $(martin_test_programs)

EXTRA_PROGRAMS = martin-test

martin_test_SOURCES = \
	martin-test.c \
	martin-test.h
	
martin_test_CFLAGS = -I$(srcdir) $(BTLS_CFLAGS)
martin_test_LDADD = $(BTLS_STATIC_LIBS)
