CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic \
          -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
          -Wredundant-decls -Wnested-externs -Wmissing-include-dirs
CFLAGS += -O2
CPPFLAGS = -std=c11
LDFLAGS = -lssl -lcrypto

TARGET = main
SRCS = main.c rsa.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

debug: CFLAGS += -DDEBUG -g
debug: $(TARGET)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.dep.mk: %.c
	$(CC) -M -MP -MT '$(<:.c=.o) $@' $(CPPFLAGS) $< > $@

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f sig.txt alice.kp valgrind-out.txt

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./$(TARGET)
