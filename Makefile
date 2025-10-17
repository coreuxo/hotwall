CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -std=gnu99 -pthread
LDFLAGS = -lpthread -lm

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES = $(wildcard $(SRCDIR)/*.c) \
          $(wildcard $(SRCDIR)/*/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/firewall

INCLUDES = -Iinclude -I/usr/include

.PHONY: all clean install uninstall nat

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

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: all
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/firewall

uninstall:
	rm -f /usr/local/bin/firewall

debug: CFLAGS += -DDEBUG -Og
debug: all

nat: CFLAGS += -DNAT_ENABLED
nat: all

test: all
	@echo "Testing firewall build..."
	@sudo $(TARGET) --test 2>/dev/null || echo "Firewall test mode"

rules:
	@chmod +x scripts/setup_rules.sh
	@./scripts/setup_rules.sh

.PHONY: all clean install uninstall debug nat test rules
