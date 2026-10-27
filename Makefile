JAVAC = javac
JAVA  = java

SOURCES = CBCMAC.java
TESTS   = CBCMACTest.java
CLASSES = $(SOURCES:.java=.class) $(TESTS:.java=.class)

ifeq ($(OS),Windows_NT)
    RM = cmd /C del /Q /F
else
    RM = rm -f
endif

.PHONY: all test tests demo clean

all: test demo

CBCMAC.class: CBCMAC.java
	$(JAVAC) CBCMAC.java

CBCMACTest.class: CBCMACTest.java CBCMAC.class
	$(JAVAC) CBCMACTest.java

test: CBCMACTest.class
	$(JAVA) CBCMACTest

tests: test

demo: CBCMAC.class
	$(JAVA) CBCMAC

clean:
	$(RM) *.class