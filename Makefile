LIBS=-lncurses
OBJS = skm.o \
       tcp_show.o udp_show.o raw_show.o \
       process.o \
       rbtree.o \
       screen.o

       
skm:${OBJS} 
	gcc -ggdb3 -o skm ${OBJS} ${LIBS}
clean:
	rm -f skm ${OBJS}	
