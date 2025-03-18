CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lm
TARGET = phishing.exe
SRC = main.c
RES = resource.o

all: $(TARGET)

$(TARGET): $(SRC) $(RES)
    $(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(RES) $(LDFLAGS)

$(RES): resource.rc
    windres resource.rc -o resource.o

clean:
    rm -f $(TARGET) $(RES)
