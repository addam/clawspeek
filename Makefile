CC = gcc
FLAGS = -lgnutls -lcrypt $(shell pkg-config --cflags --libs glib-2.0)

clawspeek: main.c
	$(CC) $^ $(FLAGS) -o $@

clean:
	rm -f clawspeek

.PHONY: clean
