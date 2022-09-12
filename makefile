
CC = gcc
TARGET = AdvancedFileSearch
CFLAGS  = -Wall

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(TARGET).c -o $(TARGET) $(CFLAGS)

clean:
	$(RM) $(TARGET)
