#include "dbg.h"

int init = 0;

void dbg_msg(char *format, ...)
{
  char buffer[512];
  va_list args;
  FILE *fp = NULL;

  va_start(args, format);
  memset(buffer, 0, sizeof (buffer));
  vsprintf_s(buffer, sizeof (buffer), format, args);
  if (!init)
  {
	   fopen_s(&fp, FILE_DBG, "w");
    init = 1;
  }
  else
	  fopen_s(&fp, FILE_DBG, "a");
  va_end(args);
  fprintf(fp, "%s", buffer);
  printf("%s", buffer);
  fclose(fp);
}

void hexdump(void *data, int size)
{
  unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for (n = 1; n <= size; n++)
  {
        if (n % 16 == 1)
    {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", ((unsigned int)p - (unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0)
    {
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - strlen(charstr) - 1);
        if (n % 16 == 0)
    {
            dbg_msg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
    else if (n % 8 == 0)
    {
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat_s(charstr, sizeof(charstr), " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }

    if (strlen(hexstr) > 0)
    {
        dbg_msg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}