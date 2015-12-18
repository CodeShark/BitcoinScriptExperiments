include mk/os.mk mk/cxx_flags.mk mk/boost_suffix.mk

INCLUDE_PATH += \
    -Isrc

LIBS = \
    -lCoinQ \
    -lCoinCore \
    -lboost_system$(BOOST_SUFFIX) \
    -lboost_regex$(BOOST_SUFFIX) \
    -lcrypto

all: build/nestedmofn${EXE_EXT} build/signnestedmofn${EXE_EXT}

build/nestedmofn${EXE_EXT}: src/nestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signnestedmofn${EXE_EXT}: src/signnestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)
