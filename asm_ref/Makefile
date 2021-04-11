all: cguiobject_killobject.bin ctextbox_killobject.bin

cguiobject_killobject.bin: cguiobject_killobject.o
	gcc cguiobject_killobject.o -nostartfiles -static -o cguiobject_killobject.bin
ctextbox_killobject.bin: ctextbox_killobject.o
	gcc ctextbox_killobject.o -nostartfiles -static -o ctextbox_killobject.bin



cguiobject_killobject.o: cguiobject_killobject.asm
	nasm -felf64 cguiobject_killobject.asm -o cguiobject_killobject.o

ctextbox_killobject.o: ctextbox_killobject.asm
	nasm -felf64 ctextbox_killobject.asm -o ctextbox_killobject.o


clean:
	rm cguiobject_killobject.o ctextbox_killobject.o cguiobject_killobject.bin ctextbox_killobject.bin
