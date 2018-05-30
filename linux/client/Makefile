TARGET := namestackclient

CFLAGS := -g -I../linux-2.6.27/include

C_SRCS := \
          main.c

OBJECTS := $(patsubst %.c,%.o,$(C_SRCS))

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LFLAGS) -o $@

.PHONY: clean
clean:
	-rm $(TARGET) $(OBJECTS)
