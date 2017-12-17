bin_PROGRAMS=tcppty

tcppty_SOURCES=main.cpp

tcppty_CPPFLAGS=-I../libs $(PTHREAD_CFLAGS) $(BOOST_CPPFLAGS)
tcppty_LDADD=-lutil -lpthread $(PTHREAD_LIBS) $(BOOST_LDFLAGS) /usr/lib/x86_64-linux-gnu/libboost_log.a /usr/lib/x86_64-linux-gnu/libboost_system.a /usr/lib/x86_64-linux-gnu/libboost_thread.a
