ASM = nasm

all: random

random: main.asm
	$(ASM) -f bin $< -o $@
	chmod +x $@

clean:
	rm -f random

.PHONY: all clean
