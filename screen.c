#include <stdio.h>
#include <stdlib.h>
#include <termio.h>

extern int screen_width;
extern int screen_length;

void get_screensize()
{
#ifdef TIOCGWINSZ
	struct winsize ws;

	if (ioctl (1, TIOCGWINSZ, &ws) != -1)
	{
		if (ws.ws_row != 0)
		{
			screen_length = ws.ws_row;
		}
		if (ws.ws_col != 0)
		{
			screen_width = ws.ws_col - 1;
		}
	}

#else
#ifdef TIOCGSIZE
	struct ttysize ts;

	if (ioctl (1, TIOCGSIZE, &ts) != -1)
	{
		if (ts.ts_lines != 0)
		{
			screen_length = ts.ts_lines;
		}
		if (ts.ts_cols != 0)
		{
			screen_width = ts.ts_cols - 1;
		}
	}

#endif 
#endif 
}
