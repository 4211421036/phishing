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
	windres -i resource.rc -o $(RES)

clean:
	rm -f $(TARGET) $(RES)
