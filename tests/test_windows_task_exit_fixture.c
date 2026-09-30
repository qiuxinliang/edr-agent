#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  unsigned long delay = 0;
  unsigned int code = 0;
  if (argc != 3 || strcmp(argv[1], "--config") != 0) return 2;
  FILE *file = fopen(argv[2], "r");
  if (!file) return 3;
  int count = fscanf(file, "%lu %x", &delay, &code);
  fclose(file);
  if (count != 2 || delay > 10000) return 4;
  Sleep(delay);
  ExitProcess((UINT)code);
}
