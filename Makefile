CC = gcc                                
CFLAGS = -fPIC -W -Wextra -g         
LDFLAGS = -shared -ldl                      
RM = rm -f                             
TARGET_LIB = logger              

SRCS = logger.c       
OBJS = $(SRCS:.c=.o)                    

.PHONY: all
all: logger logger.so

logger: $(OBJS)
		$(CC) ${CFLAGS} -o $@ $^

logger.so: liblogger.c
			$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
		-${RM} ${TARGET_LIB} logger.so ${OBJS} $(SRCS:.c=.d)