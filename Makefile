include mk/os.mk mk/cxx_flags.mk mk/boost_suffix.mk

INCLUDE_PATH += \
    -Isrc

LIBS = \
    -lCoinCore \
    -lCoinQ \
    -lboost_system$(BOOST_SUFFIX) \
    -lcrypto

all: build/1of2in2of3${EXE_EXT}

build/1of2in2of3${EXE_EXT}: src/1of2in2of3.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)
