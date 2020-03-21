#

PREFIX		?= /usr/local

TOP_DIR		= ..
BUILD_DIR	= $(TOP_DIR)/_build

CC		= gcc
CFLAGS		= -std=c11
CXX		= g++
CXXFLAGS	= -std=c++11
#CXXFLAGS	= -std=c++14
#CXXFLAGS	= -std=c++20
CPPFLAGS	=
#CPPFLAGS	+= -D__STDC_FORMAT_MACROS
#CPPFLAGS	+= -DPREFIX=\"$(PREFIX)\"

LIBS		= -lpthread
LIBS		+= -lmosquitto -lbluetooth -luuid
OBJS		= ble_beacon.o gateway.o filters.o logger.o
BINS		= beacon2mqtt

OBJS		:= $(OBJS:%=$(BUILD_DIR)/%)
BINS		:= $(BINS:%=$(BUILD_DIR)/%)

all::	$(BINS)
clean::;	rm -f *~
veryclean::	clean
	rm -rf $(BUILD_DIR)
	rm -f Makefile.depend
install::

$(BUILD_DIR)/%.o:	%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

$(BUILD_DIR)/%.o:	%.cc
	@mkdir -p $(BUILD_DIR)
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) -c $<

# work-around
$(BUILD_DIR)/main.o:	main.cc
	$(CXX) -o $@ $(CPPFLAGS) $(CXXFLAGS) -c $<

$(BUILD_DIR)/beacon2mqtt:	$(OBJS) $(BUILD_DIR)/main.o
	$(CXX) -o $@ $^ $(LIBS)

install::	all
	@mkdir -p $(PREFIX)/bin
	cp -fp $(BINS) $(PREFIX)/bin

#
-include Makefile.depend

Makefile.depend:	$(shell echo *.h *.c *.cc)
	@rm -f $@ && touch $@
#	@echo "# SRC_DIRS = $(SRC_DIRS)" >> $@
	$(CPP) -I. -MM $^ 2> /dev/null |\
	while read LINE; do \
	echo $$LINE | sed -r 's/:/ : /g' |\
	gawk -v dir=$(BUILD_DIR) 'BEGIN{FS="[ \t:]+"}/^[^:]/{printf("%s/%s ",dir,gensub(/^(\.\/)?(.*)/,"\\2","1",$$0));next}{printf("%s ",$$0)}END{printf("\n")}';\
	done >> $@
	@echo >> $@
	@echo "# generated at: `date +%Y-%m-%dT%H:%M:%S%z`" >> $@
