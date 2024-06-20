CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic \
          -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
          -Wredundant-decls -Wnested-externs -Wmissing-include-dirs
CFLAGS += -std=c11
CFLAGS += -L/usr/lib -I/usr/lib
LDFLAGS = -lssl -lcrypto

TARGET = main
SRCS = main.c util.c rsa.c verify.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

debug: CFLAGS += -DDEBUG -g
debug: CFLAGS += -O0
debug: $(TARGET)

all: CFLAGS += -O2
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f valgrind-out.txt

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./$(TARGET) decrypt other.txt
