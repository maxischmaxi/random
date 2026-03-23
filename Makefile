ASM = nasm

linux: linux_x86_64.asm
	$(ASM) -f bin $< -o random-linux-x86_64
	chmod +x random-linux-x86_64

macos-intel: macos_x86_64.asm
	$(ASM) -f macho64 $< -o macos_x86_64.o
	ld -arch x86_64 -e _start -o random-macos-x86_64 macos_x86_64.o -lSystem -syslibroot $$(xcrun --show-sdk-path)

macos-arm: macos_arm64.s
	as $< -o macos_arm64.o
	ld -e _start -o random-macos-arm64 macos_arm64.o -lSystem -syslibroot $$(xcrun --show-sdk-path)

windows: windows_x86_64.asm
	$(ASM) -f win64 $< -o windows_x86_64.obj
	link /nodefaultlib /subsystem:console /entry:_start /out:random-windows-x86_64.exe windows_x86_64.obj kernel32.lib bcrypt.lib

clean:
	rm -f random-* *.o *.obj

.PHONY: linux macos-intel macos-arm windows clean
