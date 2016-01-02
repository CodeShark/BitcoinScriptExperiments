include mk/os.mk mk/cxx_flags.mk mk/boost_suffix.mk

INCLUDE_PATH += \
    -Isrc

LIBS = \
    -lCoinQ \
    -lCoinCore \
    -lboost_system$(BOOST_SUFFIX) \
    -lboost_regex$(BOOST_SUFFIX) \
    -lcrypto

all: no_lib_support build/signwitnesstx${EXE_EXT}

no_lib_support: build/nestedmofn${EXE_EXT} build/signnestedmofn${EXE_EXT} build/cltv${EXE_EXT} build/signcltv${EXE_EXT} build/witness${EXE_EXT} build/signwitness${EXE_EXT}

build/nestedmofn${EXE_EXT}: src/nestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signnestedmofn${EXE_EXT}: src/signnestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/cltv${EXE_EXT}: src/cltv.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signcltv${EXE_EXT}: src/signcltv.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/witness${EXE_EXT}: src/witness.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signwitness${EXE_EXT}: src/signwitness.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signwitnesstx${EXE_EXT}: src/signwitnesstx.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)
