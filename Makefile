CC = gcc
FLAGS = -lgnutls -lcrypt $(shell pkg-config --cflags --libs glib-2.0 nettle)

clawspeek: main.c
	$(CC) $^ $(FLAGS) -o $@

clean:
	rm -f clawspeek

.PHONY: clean
