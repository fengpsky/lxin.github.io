---
layout: post
title: "socket example for test "
category: auto test
excerpt: 测试中常用到的sokcet例子
tags: [kernel]
---
{% include JB/setup %}

## DCCP

###server

    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <string.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <errno.h>

    #define MAX_DCCP_CONNECTION_BACK_LOG 5
    #define SOL_DCCP        269

    int main()
    {
            struct sockaddr_in mLocalName, mRemoteName;
            int mRemoteLength, result;
            int mSocketHandle, mClientSocketHandle;
            char receive_buff[100];
            int on = 1;
            mSocketHandle = socket(PF_INET, SOCK_DCCP, IPPROTO_DCCP);
            result = setsockopt(mSocketHandle, SOL_DCCP, SO_REUSEADDR, (const char *) &on, sizeof(on));
            if (result < 0){
                    perror("error");
            }

            mLocalName.sin_family = AF_INET;
            mLocalName.sin_port = htons(104);
            mLocalName.sin_addr.s_addr = htonl(INADDR_ANY);
            result = bind(mSocketHandle, (struct sockaddr *)&mLocalName, sizeof(mLocalName));
            if (result < 0){
                    perror("error");
            }
            result = listen(mSocketHandle, MAX_DCCP_CONNECTION_BACK_LOG);
            if (result < 0){
                    perror("error");
            }
            mClientSocketHandle = accept(mSocketHandle, (struct sockaddr *)&mRemoteName, &mRemoteLength);
            memset(receive_buff, 0, sizeof(receive_buff));
            result = recv(mClientSocketHandle, receive_buff, 100, 0);
            if (result < 0){
                    perror("error");
            }
            printf("%s\n", receive_buff);
            sleep(3600);
            close(mSocketHandle);

    }


###client

    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <string.h>
    #include <stdio.h>
    #include <errno.h>
    #define MAX_DCCP_CONNECTION_BACK_LOG 5
    #define SOL_DCCP        269

    int main()
    {
            struct sockaddr_in mLocalName, mRemoteName;
            char sendbuffer[100];
            int mSocketHandle;
            int result;
            int on = 1;

            mRemoteName.sin_family = AF_INET;
            mRemoteName.sin_port = htons(104);
            mRemoteName.sin_addr.s_addr = inet_addr("192.168.0.20");

            mSocketHandle = socket(PF_INET, SOCK_DCCP, IPPROTO_DCCP);
            result = setsockopt(mSocketHandle, SOL_DCCP, SO_REUSEADDR, (const char *) &on, sizeof(on));
            if(result < 0){
                    perror("error");
            }
            result = connect(mSocketHandle, (struct sockaddr *)&mRemoteName, sizeof(mRemoteName));
            if(result < 0){
                    perror("error");
            }

            memset(sendbuffer, 0, sizeof(sendbuffer));
            sprintf(sendbuffer,"testing");
            do{
                    result = send(mSocketHandle, sendbuffer, 100, 0);
            }while(0);//(status<0)&&(errno == EAGAIN));
            sleep(3600);
            close(mSocketHandle);

    }

##TCP

##sever

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    #include <arpa/inet.h>
    #include <sys/socket.h>

    int main( int argc , char ** argv )
    {
        struct sockaddr_in saddr, caddr;

        char buf[100] ;
        char str[100] ;

        int listenfd, connfd;
        int addr_len;

        listenfd = socket( AF_INET, SOCK_STREAM, 0 );

        memset ( &saddr, 0, sizeof(saddr) );
        memset( buf, 0, 100 );
        memset( buf, 0, 100 );
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons( 8001 );
        saddr.sin_addr.s_addr = htonl( INADDR_ANY );

        bind( listenfd, (struct sockaddr *)&saddr, 16 );

        listen( listenfd, 20 );

        printf( "Accepting connections ... \n" );

        int i, n;
        while(1)
        {
            addr_len = sizeof( caddr );
            connfd = accept( listenfd, (struct sockaddr*)&caddr, &addr_len );

            n = recv( connfd, buf, 100, 0  );

            printf("Recive from %s : %d \n",  inet_ntop( AF_INET, &caddr.sin_addr, str, sizeof(str) ), ntohs(caddr.sin_port) );

            for(i=0; i<n; i++)
            {
                buf[i] = toupper( buf[i] );
            }

            send( connfd, buf, n+1, 0 );

            printf("Send : %s \n", buf);
            close( connfd );
        }

        return 0;
    }

###client

    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>


    int main( int argc, char** argv )
    {
        struct sockaddr_in server_addr_in;
        char buf[100];

        int cfd;
        int port = 8001;

        char *str = "test string";

        if( argc > 1 )
        {
            str = argv[1];
        }

        cfd = socket( AF_INET, SOCK_STREAM, 0 );

        bzero( &server_addr_in, sizeof(server_addr_in) );

        server_addr_in.sin_family = AF_INET;
        server_addr_in.sin_port = htons(port);
        inet_pton( AF_INET, "192.168.4.5", &server_addr_in.sin_addr );

        connect( cfd, (struct sockaddr *)&server_addr_in, sizeof(server_addr_in) );

        send( cfd, str, strlen(str)+1, 0 );
        recv( cfd, buf, 100, 0 );

        close(cfd);

        printf("Recive from server : %s \n", buf);

        return 0;
    }
