#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

int main(int argc, char **argv)
{
    int sockfd=0, n=0;
    char recvBuff[1024];
    struct sockaddr_in serv_addr;
    char message [100];
    int done;
    int number;
    char tmpstr [30];
    int received; 
    char ans;
/* kreiraj socket za komunikaciju sa serverom */
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
    printf("\n Error : Could not create socket \n");
    return 1;
    }
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    /*podaci neophodi za komunikaciju sa serverom*/
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(4500);
        /* inet_pton konvertuje ip adresu iz stringa u format
    neophodan za serv_addr strukturu */
    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
    {
    printf("\n inet_pton error occured\n");
    return 1;
    } 
        /* povezi se sa serverom definisanim preko ip adrese i porta */
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
    printf("\n Error : Connect Failed \n");
    return 1;
    }
    done = 0;
    n = read (sockfd, recvBuff, 1024);
        recvBuff[n] = 0; //terminiraj primljeni string kako bi ga mogao ispisati
        printf("Kvadrant je: id%s\n",recvBuff);
        printf("Ako zelite da prekinete komunikaciju sa serverom ukucajte 'Q'\n");
        printf("Ako zelite da pomijerate kvadrat, ukucajte jedan od karaktera (W,S,A,D)\n");
    while(1)
    {
        
        ans = getchar();
        write (sockfd, &ans,1);
        if (ans == 'q') 
        {
            return 0;
        }
    
        
        
    }
    return 0;
        
}