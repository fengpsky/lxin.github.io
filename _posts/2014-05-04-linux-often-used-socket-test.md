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
