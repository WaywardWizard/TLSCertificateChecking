# Author: Ben Tomlin
# 	  SN: 834198
#   Date: 19thMay2018
CC			= gcc
CFLAG		= -g -iquote $(UTILITY_PATH)
CFLAGTRAIL  = -lssl -lcrypto -lm
EXE			= certcheck
LINK_OBJECT = certVerifier.o regexTool.o logger.o dataStructure.o csvTool.o
UTILITY_PATH= utility/

all: $(EXE)

$(EXE): $(LINK_OBJECT) certVerifier.c certVerifier.h
	$(CC) $(CFLAG) -o $(EXE) $(LINK_OBJECT) $(CFLAGTRAIL)
	
certVerifier.o: certVerifier.c certVerifier.h
	$(CC) $(CFLAG) -c certVerifier.c $(CFLAGTRAIL)

csvTool.o: $(UTILITY_PATH)csvTool.c $(UTILITY_PATH)csvTool.h
	$(CC) $(CFLAG) -c $(UTILITY_PATH)csvTool.c $(CFLAGTRAIL)
	
regexTool.o: $(UTILITY_PATH)regexTool.c $(UTILITY_PATH)regexTool.h
	$(CC) $(CFLAG) -c $(UTILITY_PATH)regexTool.c $(CFLAGTRAIL)

logger.o: $(UTILITY_PATH)logger.c $(UTILITY_PATH)logger.h
	$(CC) $(CFLAG) -c $(UTILITY_PATH)logger.c $(CFLAGTRAIL)

dataStructure.o: $(UTILITY_PATH)dataStructure.c $(UTILITY_PATH)dataStructure.h
	$(CC) $(CFLAG) -c $(UTILITY_PATH)dataStructure.c $(CFLAGTRAIL)


clean:
	rm $(EXE) *.o
