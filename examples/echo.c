#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;
  // printf("hahahahahha %s", (char*)0xc1234); // 此处发生异常，说明已经进入该用户程序，printf是一个系统调用
  // printf ("\n");
  // printf("hahaha");
  for (i = 0; i < argc; i++)
  {
    printf ("%s ", argv[i]);
    // if (*(char*)(argv[i]+1)=='\0')
    //   printf("hahaha");
  }
  printf ("\n");

  return EXIT_SUCCESS;
}
