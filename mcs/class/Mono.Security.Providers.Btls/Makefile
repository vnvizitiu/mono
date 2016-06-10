thisdir = class/Mono.Security.Providers.Btls
SUBDIRS = 
include ../../build/rules.make

LIBRARY = Mono.Security.Providers.Btls.dll
LIB_REFS = System Mono.Security
LIB_MCS_FLAGS = -unsafe -nowarn:1030 -keyfile:../mono.pub -delaysign -d:SECURITY_DEP

include ../../build/library.make

$(the_lib): ../Mono.Security/Makefile

