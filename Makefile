CC = gcc
CFLAGS = -Wall -Wextra -pedantic
LDFLAGS = -lssl -lcrypto

TARGET = main
SRCS = main.c
OBJS = $(SRCS:.c=.o)

debug: CFLAGS += -DDEBUG -g
debug: $(TARGET)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)