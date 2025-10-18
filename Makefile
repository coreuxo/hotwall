CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=gnu99 -pthread
LDFLAGS = -lpthread -lm -lreadline

SRCDIR = src
OBJDIR = obj
BINDIR = bin
TESTDIR = tests

SOURCES = $(wildcard $(SRCDIR)/*.c) \
          $(wildcard $(SRCDIR)/*/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/firewall
TEST_TARGET = $(BINDIR)/firewall_test
INTEGRATION_TARGET = $(BINDIR)/integration_test

INCLUDES = -Iinclude -I/usr/include

.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(BINDIR):
	@mkdir -p $(BINDIR)

test: $(TEST_TARGET) $(INTEGRATION_TARGET)

$(TEST_TARGET): $(TESTDIR)/test_runner.c $(filter-out $(OBJDIR)/main.o, $(OBJECTS))
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

$(INTEGRATION_TARGET): $(TESTDIR)/integration_test.c $(filter-out $(OBJDIR)/main.o, $(OBJECTS))
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: all
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/firewall
	mkdir -p /etc/firewall
	cp config/firewall.conf /etc/firewall/

uninstall:
	rm -f /usr/local/bin/firewall

debug: CFLAGS += -DDEBUG=1 -Og
debug: all

prod: CFLAGS += -O3 -DNDEBUG
prod: all

check: test
	./scripts/run_tests.sh

.PHONY: all clean install uninstall debug prod test check
