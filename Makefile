include mk/os.mk mk/cxx_flags.mk mk/boost_suffix.mk

INCLUDE_PATH += \
    -Isrc

LIBS = \
    -lCoinCore \
    -lCoinQ \
    -lboost_system$(BOOST_SUFFIX) \
    -lboost_regex$(BOOST_SUFFIX) \
    -lcrypto

all: build/nestedmofn${EXE_EXT}

build/nestedmofn${EXE_EXT}: src/nestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)
