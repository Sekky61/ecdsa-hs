# makefile for a haskell project

# all sources are in src directory
SOURCE=$(wildcard src/*.hs)

# the name of the project
PROJECT = flp22-fun

# the name of the executable
EXECUTABLE = $(PROJECT)

EXECUTABLE: $(SOURCE)
	ghc -o $(EXECUTABLE) $(SOURCE) -Wall

clean:
	rm -f $(EXECUTABLE) src/*.hi src/*.o
