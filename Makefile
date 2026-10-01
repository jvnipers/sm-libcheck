# Checkout: git clone --recursive -b 1.12-dev https://github.com/alliedmodders/sourcemod
SM ?= ../sourcemod
CXX ?= g++

# Defines match what SM's own extension builds pass.
CXXFLAGS = -m32 -std=c++17 -O2 -fPIC -Wall \
	-D_LINUX -DPOSIX -DGNUC -DHAVE_STDINT_H \
	-Dstricmp=strcasecmp -D_stricmp=strcasecmp -D_snprintf=snprintf -D_vsnprintf=vsnprintf \
	-I. -I$(SM)/public -I$(SM)/public/extensions -I$(SM)/sourcepawn/include \
	-I$(SM)/public/amtl -I$(SM)/public/amtl/amtl

# Static libstdc++/libgcc: a library checker shouldn't itself fail on a GLIBCXX mismatch.
LDFLAGS = -m32 -shared -static-libstdc++ -static-libgcc -ldl

.DELETE_ON_ERROR:

libcheck.ext.so: extension.cpp smsdk_config.h buildenv_libs.h $(SM)/public/smsdk_ext.cpp
	$(CXX) $(CXXFLAGS) extension.cpp $(SM)/public/smsdk_ext.cpp -o $@ $(LDFLAGS)

buildenv_libs.h: gen_buildenv_libs.sh
	sh gen_buildenv_libs.sh > $@

clean:
	rm -f libcheck.ext.so buildenv_libs.h
