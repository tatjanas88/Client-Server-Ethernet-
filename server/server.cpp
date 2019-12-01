#include <arpa/inet.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <bits/types/siginfo_t.h>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */

#define VGA_X 640
#define VGA_Y 480
#define BLACK 0x0000
#define RED 0xF800
#define BLUE 0x001F
#define MAX_MMAP_SIZE (VGA_X * VGA_Y * sizeof(unsigned int)) //zato sto nemaju svi procesori istu sirinu tipova(int moze biti 16,32,64)

void sock_write(int sockfd, std::string s) {
  write(sockfd, s.c_str(), s.size());
}

std::string sock_read(int sockfd) {
  const int MAX = 256;
  char buff[MAX];
  bzero(buff, MAX);
  read(sockfd, buff, sizeof(buff));
  std::string message(buff);

  return message;
}
void rect_draw(int x1, int x2, int y1, int y2, int color, int *buf);//crtanje pravougaonika
void clear_section(int* buff, int clinum) {
  if (clinum == 0) {
    rect_draw(0, VGA_X / 2 - 1, 0, VGA_Y / 2 - 1, BLACK,buff);
  } else if (clinum == 1) {
    rect_draw(VGA_X / 2 + 1, VGA_X - 1, 0, VGA_Y / 2 - 1, BLACK,buff);
  } else if (clinum == 2) {
    rect_draw(0, VGA_X / 2 - 1, VGA_Y / 2 + 1, VGA_Y - 1, BLACK,buff);
  } else if (clinum == 3) {
    rect_draw(VGA_X / 2 + 1, VGA_X - 1, VGA_Y / 2 + 1, VGA_Y - 1,
                    BLACK,buff);
  }
}

void draw_rect(int *buff, int clinum, int x_off, int y_off) { //iscrtavanje prav. u odnosu na offset u odr. kvadrantu
  if (clinum == 0) {
    rect_draw(VGA_X / 4 - 20 + x_off, VGA_X / 4 + 20 + x_off,
                    VGA_Y / 4 - 20 + y_off, VGA_Y / 4 + 20 + y_off, RED,buff);
  } else if (clinum == 1) {
    rect_draw((3 * VGA_X / 4) - 20 + x_off, (3 * VGA_X / 4) + 20 + x_off,
                    VGA_Y / 4 - 20 + y_off, VGA_Y / 4 + 20 + y_off, RED,buff);
  } else if (clinum == 2) {
    rect_draw(VGA_X / 4 - 20 + x_off, VGA_X / 4 + 20 + x_off,
                    (3 * VGA_Y / 4) - 20 + y_off, (3 * VGA_Y / 4) + 20 + y_off,
                    RED,buff);
  } else if (clinum == 3) {
    rect_draw((3 * VGA_X / 4) - 20 + x_off, (3 * VGA_X / 4) + 20 + x_off,
                    (3 * VGA_Y / 4) - 20 + y_off, (3 * VGA_Y / 4) + 20 + y_off,
                    RED,buff);
  }
}

void saturate_section(int *x_off, int *y_off) { //ogranicavanje kvadranta za pomijeranje prav.  a to su poz relativno u odn na sredinu kvadranta
  if (*x_off < -VGA_X / 4 + 21) //da bi mogli mijenjati tu prom mora preko pok
    *x_off = -VGA_X / 4 + 21;
  if (*x_off > VGA_X / 4 - 21)
    *x_off = VGA_X / 4 - 21;

  if (*y_off < -VGA_Y / 4 + 21)
    *y_off = -VGA_Y / 4 + 21;
  if (*y_off > VGA_Y / 4 - 21)
    *y_off = VGA_Y / 4 - 21;
}

void move_rect(int *buff, int clinum, std::string cmd, int *x_off, int *y_off) {
  clear_section(buff, clinum);
  if (cmd == "w\n")
    *y_off = *y_off - 10;
  else if (cmd == "s\n")
    *y_off = *y_off + 10;
  else if (cmd == "d\n")
    *x_off = *x_off + 10;
  else if (cmd == "a\n")
    *x_off = *x_off - 10;

  saturate_section(x_off, y_off); //provjera granica nakon offseta
  draw_rect(buff, clinum, (*x_off), (*y_off));
}

std::string sec_n_to_str(int n) { //broj kvadranta u string
  if(n == 0)
    return "Top left";
  if(n == 1)
    return "Top right";
  if(n == 2)
    return "Bottom left";
  if(n == 3)
    return "Bottom right";

  return "Undefined";
}
int zauzmi_kvadrant(int *pids, int pid) {
  for (int i = 0; i < 4; i++) {
    if (pids[i] == 0) {
      pids[i] = pid;
      return i;
    }
  }
  return -1;
}

void ispisivanje_liste(int *pids, int n) {
  std::cout << "Client list: ";
  for (int i = 0; i < n; i++)
    std::cout << pids[i] << " ";
    std::cout << "\n";
}

int oslobadjanje_kvadranta(int *pids, int pid) {
  for (int i = 0; i < 4; i++) {
    if (pids[i] == pid) {
      pids[i] = 0;
      return i;
    }
  }
  return -1;
}

int prvi_slobodan_kvadrant(int *pids, int n) {
  for (int i = 0; i < n; i++) {
    if (pids[i] == 0)
      return i;
  }
  return -1;
}

void lineh_draw(int x1, int x2, int y, int color, int *buf)//funkcija za crtanje vertikalne l. (proslijedjuju se koord.,boja i pok.na memoriju koju ce prebojiti)
{
    for(int x=x1; x<=x2; x++)
    {   /*zato sto memorija ima jednu dimenziju---redove moramo da dodamo na kolone-kao offset*/
        buf[y*VGA_X + x] = color;
    }
}
void linev_draw(int y1, int y2, int x, int color, int *buf)//crtanje horiz.linije
{
    for(int y=y1; y<=y2; y++)
    {   /*isto kao u prethodnom slucaju*/
        buf[y*VGA_X + x] = color;
    }
}
void rect_draw(int x1, int x2, int y1, int y2, int color, int *buf)//crtanje pravougaonika
{
    for (int x=x1;x<=x2;x++)
    {
        for(int y=y1; y<=y2; y++)
        {
            buf[y*VGA_X + x] = color;//ovo vazi u svakom slucaju
        }
    }
}
void background_fill(int color, int *buf)//bojenje pozadine je isto kao bojenje pravougaonika velicine(rezolucije) ekrana
{
    rect_draw(0, VGA_X-1,0, VGA_Y-1, color, buf);
}
int get_color(std::string c) //funkcija koja ce pokupiti string=boju
{
  if (c == "BLUE")
    return BLUE;
  if (c == "RED")
    return RED;
  if (c == "BLACK")
    return BLACK;
  
  return BLACK;
}

int main()
{
     //ovaj dio je preuzet sa git-a....rad sa VGA drajverom preko memorijskog mapiranja//
    int *buffer;
    int fd;
    int klijent = 0;
    int nizid[4]={0}; 
    int id;
    int pid;
    fd = shm_open("vga_buffer", O_RDWR,0666);
    if (fd < 0)
    {
      printf("Cannot open vga_buffer\n");;
      exit(EXIT_FAILURE);
    }
    else
        /* memorijski mapiraj vga_dma na buffer*/
    buffer = (int *)mmap(0, MAX_MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        /*&line_buff je pokazivac na buffer gdje ce funk.smjestiti podatke procitane iz fajla=nealociran i prazan*/
        /*pokazivac na promenjivu koja sadrzi velicinu bafera=u mom slucaju to je nula, a poslije citanja ce sadrzati broj procitanih bajtova iz fajla*/
        /*pok je pokazivac na moj fajl*/
    int sockfd, newsockfd, portno, clilen;
    struct sockaddr_in serv_addr, cli_addr; //struct tipa sockaddr_in za klijenta i za server
    //kreiraj socket (1.IP protokol- af inet koristi IPV4, 2.da li koristimo STREAM ili datagram pakete, koristimo TCP stream, 3.koji protokol koristimo, 0 onda se uyima podrayumevani protokol za ovaj tip komunik.)
    sockfd = socket (AF_INET, SOCK_STREAM, 0); //vraca socket file descriptor(int) - preko sockfd cemo koristiti kreirani socket
    if (sockfd < 0) //socket je IP+PORT
    {
        perror("ERROR opening cocket");
        exit(1);
    } //NAKON OVOG TREBA URADITI BIND, BIND OMOGUCAVA DA ZNAMO KOJI IP I KOJI PORT KORISTIM ZA SLUSANJE KLIJENTA, za to se koristi struct serv_addr
    /*inicijalozija serverske strukture/ popune se njena polja*/

    background_fill(BLACK,buffer);
    lineh_draw(0,639,240,BLUE,buffer);
    linev_draw(0,479,320,BLUE,buffer);
    bzero((char*) &serv_addr, sizeof(serv_addr)); //sve u pocetku postavu na 0
    portno=4500;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY; //Postavlja IP ADRESU HOSTA / daje adresu servera na kom smo pokrenuli prog.
    serv_addr.sin_port = htons(portno); //vraca u pravom formatu za struct
    /*bindovanje*/
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))<0) //tom socketu se postavlja struktura serv-addr koja je odg velicine, znaci nas socket ce odsas koristiti IP a i P koji smo def
    {
        perror("ERROR on binding");
        exit(1);
    }
    printf(" server started || Waiting for clients...\n");
    listen(sockfd,4); //max 4 klijenta
    clilen = sizeof(cli_addr);
    while(1)
    {
        /*ceka se zahtjev za konekcijom prvog klijenta*/
        if(nizid[0]==0 || nizid[1]==0 || nizid[2]==0 || nizid[3]==0)
        {
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); //neblokirajuci
        newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr, (socklen_t *)&clilen); //blokira se program i ceka klijenta, newsock je novi identifikator preko koga pricamo dalje s tim klijentom
        if (newsockfd == -1) {
            /* If socket failed because there were no client requests, sleep 10ms */
            if (errno == EWOULDBLOCK) {
                usleep(10000);
                }
        /* Otherwise accept() failed with an error */
        else {
          std::cerr << "ERROR while accepting\n";
          exit(1);
            }
        }
        else {
        std::string cli_ip_str = inet_ntoa(cli_addr.sin_addr);
        /* Revert socket config to BLOCKING */
        int flags = fcntl(newsockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags & (~O_NONBLOCK));
        int first_free = prvi_slobodan_kvadrant(nizid, 4);
        std::cout << "Client with IP: " << cli_ip_str
                  << " connected to section " << sec_n_to_str(first_free)
                  << "\n";
        pid = fork();
        if (pid < 0) {
          std::cerr << "ERROR while forking\n";
          exit(1);
        }
        /* Child process serves the client
           Child process is terminating after if block
         */
        if (pid == 0) {
          int x_off = 0;
          int y_off = 0;
          clear_section(buffer, first_free);
          draw_rect(buffer, first_free, 0, 0);
          close(sockfd);
          sock_write(newsockfd, "Controlling: " + sec_n_to_str(first_free)); //da bi vracali string...konkatenacija stringova
          std::string msg;
          do {
            msg = sock_read(newsockfd); //da bi vracali string
            std::cout<<msg<<std::endl;
            move_rect(buffer, first_free, msg, &x_off, &y_off);
          } while (msg != "q\n" && msg != "");
          clear_section(buffer, first_free);
          close(newsockfd);

          exit(0);
        }
        /* Parent process add connected client to list
           Occupy free position in client list 'pids'
         */
        else {
          close(newsockfd);
          zauzmi_kvadrant(nizid, pid);
          ispisivanje_liste(nizid, 4);
        }
      }
        }
            
            /* Parrent process
       Checks if any of the child processes has terminated (client disconnected)
       On client disconnect release entry in PID list
     */
    for (int a = 0; a < 4; a++) {
      if (nizid[a] != 0) {
        int status;
        if (waitpid(nizid[a], &status, WNOHANG)) {
          std::cout << "Client disconnected\n";
         for (int i = 0; i < 4; i++) {
            if (nizid[i] == pid) {
                nizid[i] = 0;         
            }
        } 
          ispisivanje_liste(nizid, 4);
        }
      }
    }
    
        
    } /*end of while*/
    munmap(buffer, MAX_MMAP_SIZE);
    close(fd);
    if (fd < 0)
    printf("Cannot close vga_buffer\n");
    close(sockfd);
    return 0;
      
}
