include mk/os.mk mk/cxx_flags.mk mk/boost_suffix.mk

INCLUDE_PATH += \
    -Isrc

LIBS = \
    -lCoinQ \
    -lCoinCore \
    -lboost_system$(BOOST_SUFFIX) \
    -lboost_regex$(BOOST_SUFFIX) \
    -lcrypto

NO_LIB_SUPPORT = \
    build/nestedmofn${EXE_EXT} \
    build/signnestedmofn${EXE_EXT} \
    build/cltv${EXE_EXT} \
    build/signcltv${EXE_EXT} \
    build/signcsv${EXE_EXT} \
    build/witness${EXE_EXT} \
    build/signwitness${EXE_EXT}

LIB_SUPPORT = \
    build/mofn${EXE_EXT} \
    build/createmofntx${EXE_EXT} \
    build/signmofntx${EXE_EXT} \
    build/signwitnesstx${EXE_EXT} \
    build/witnessmofn${EXE_EXT} \
    build/createwitnessmofntx${EXE_EXT} \
    build/signwitnessmofntx${EXE_EXT}

all: no_lib_support ${LIB_SUPPORT}

no_lib_support: ${NO_LIB_SUPPORT} 

build/mofn${EXE_EXT}: src/mofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/createmofntx${EXE_EXT}: src/createmofntx.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signmofntx${EXE_EXT}: src/signmofntx.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/nestedmofn${EXE_EXT}: src/nestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signnestedmofn${EXE_EXT}: src/signnestedmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/cltv${EXE_EXT}: src/cltv.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signcltv${EXE_EXT}: src/signcltv.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signcsv${EXE_EXT}: src/signcsv.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/witness${EXE_EXT}: src/witness.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signwitness${EXE_EXT}: src/signwitness.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signwitnesstx${EXE_EXT}: src/signwitnesstx.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/witnessmofn${EXE_EXT}: src/witnessmofn.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/createwitnessmofntx${EXE_EXT}: src/createwitnessmofntx.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

build/signwitnessmofntx${EXE_EXT}: src/signwitnessmofntx.cpp
	$(CXX) $(CXX_FLAGS) $(INCLUDE_PATH) $^ -o $@ $(LIBS)

clean:
	-rm -rf ${NO_LIB_SUPPORT} ${LIB_SUPPORT}
