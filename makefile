LDLIBS += -lpcap

all: airodump


airodump.o: radiotap_iter.h airodump.h airodump.c

radiotap.o: platform.h radiotap.h radiotap_iter.h radiotap.c

main.o: airodump.h main.cpp

airodump: airodump.o radiotap.o main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o



