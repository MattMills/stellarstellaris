all: cguiobject_killobject.bin ctextbox_killobject.bin cspinner_killobject.bin cinstanttextbox_killobject.bin \
	cfleetview_update.bin cmapiconmanager_updategalacticobjecticons.bin cplanetview_update.bin \
	cguigraphics_render2dtree.bin

cguiobject_killobject.bin: cguiobject_killobject.o
	gcc cguiobject_killobject.o -nostartfiles -static -o cguiobject_killobject.bin
ctextbox_killobject.bin: ctextbox_killobject.o
	gcc ctextbox_killobject.o -nostartfiles -static -o ctextbox_killobject.bin

cspinner_killobject.bin: cspinner_killobject.o
	gcc cspinner_killobject.o -nostartfiles -static -o cspinner_killobject.bin

cinstanttextbox_killobject.bin: cinstanttextbox_killobject.o
	gcc cinstanttextbox_killobject.o -nostartfiles -static -o cinstanttextbox_killobject.bin

cfleetview_update.bin: cfleetview_update.o
	gcc cfleetview_update.o -nostartfiles -static -o cfleetview_update.bin
cmapiconmanager_updategalacticobjecticons.bin: cmapiconmanager_updategalacticobjecticons.o
	gcc cmapiconmanager_updategalacticobjecticons.o -nostartfiles -static -o cmapiconmanager_updategalacticobjecticons.bin

cplanetview_update.bin: cplanetview_update.o
	gcc cplanetview_update.o -nostartfiles -static -o cplanetview_update.bin



cguigraphics_render2dtree.bin: cguigraphics_render2dtree.o
	        gcc cguigraphics_render2dtree.o -nostartfiles -static -o cguigraphics_render2dtree.bin


cguiobject_killobject.o: cguiobject_killobject.asm
	nasm -felf64 cguiobject_killobject.asm -o cguiobject_killobject.o

ctextbox_killobject.o: ctextbox_killobject.asm
	nasm -felf64 ctextbox_killobject.asm -o ctextbox_killobject.o

cspinner_killobject.o: cspinner_killobject.asm
	nasm -felf64 cspinner_killobject.asm -o cspinner_killobject.o
cinstanttextbox_killobject.o: cinstanttextbox_killobject.asm
	nasm -felf64 cspinner_killobject.asm -o cinstanttextbox_killobject.o

cfleetview_update.o: cfleetview_update.asm
	nasm -felf64 cfleetview_update.asm -o cfleetview_update.o
cmapiconmanager_updategalacticobjecticons.o: cmapiconmanager_updategalacticobjecticons.asm
	nasm -felf64 cmapiconmanager_updategalacticobjecticons.asm -o cmapiconmanager_updategalacticobjecticons.o

cplanetview_update.o: cplanetview_update.asm 
	nasm -felf64 cplanetview_update.asm -o cplanetview_update.o

cguigraphics_render2dtree.o: cguigraphics_render2dtree.asm
	nasm -felf64 cguigraphics_render2dtree.asm -o cguigraphics_render2dtree.o

clean:
	rm cguiobject_killobject.o cguiobject_killobject.bin \
		ctextbox_killobject.o ctextbox_killobject.bin \
		cspinner_killobject.o cspinner_killobject.bin \
		cinstanttextbox_killobject.o cinstanttextbox_killobject.bin \
		cfleetview_update.o cfleetview_update.bin \
		cmapiconmanager_updategalacticobjecticons.o cmapiconmanager_updategalacticobjecticons.bin \
		cplanetview_update.o cplanetview_update.bin \
		cguigraphics_render2dtree.o cguigraphics_render2dtree.bin
