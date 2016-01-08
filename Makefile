GMPDIR=/home-reseau/bviguier/gmp
CC=g++
BIN=bin
INCLUDE=-I cipher -I includes -I $(GMPDIR)/include 
CFLAGS=-c -pedantic -O2 -Wall -Wextra -fopenmp -std=c++11 $(INCLUDE)
LDFLAGS=-std=c++11 -lgmpxx -lgmp -fopenmp
LIB=-L $(GMPDIR)/lib
SOURCES=$(wildcard cipher/*.cpp) $(wildcard cryptanalysis/*.cpp) $(wildcard tools/*.cpp) main.cpp 
OBJECTS=$(addprefix $(BIN)/, $(notdir $(SOURCES:.cpp=.o)))
EXECUTABLE=$(BIN)/main
vpath %.cpp includes:tools:cipher:cryptanalysis

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(LIB) $(OBJECTS) -o $@

-include $(BIN)/$(OBJECTS:.o=.d)

$(BIN)/%.o: %.cpp
	$(CC) -c $(CFLAGS) $< -o $(BIN)/$*.o
	$(CC) -MM $(CFLAGS) $< > $(BIN)/$*.d 
	@mv -f $(BIN)/$*.d $(BIN)/$*.d.tmp
	@sed -e 's|.*:|$(BIN)/$*.o:|' < $(BIN)/$*.d.tmp > $(BIN)/$*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $(BIN)/$*.d.tmp | fmt -1 | \
	sed -e 's/^ *//' -e 's/$$/:/' >> $(BIN)/$*.d
	@rm -f $(BIN)/$*.d.tmp

clean:
	rm -f $(BIN)/*.o $(BIN)/*.d $(EXECUTABLE)
