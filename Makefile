CC = g++
LDFLAGS = -lpcap
TARGET = pcap_test
SOURCE = pcap_test.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm $(TARGET)