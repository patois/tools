#include "gpdef.h"
#include "gpstdlib.h"
#include "gpgraphic.h"
#include "gpmain.h"
#include "gpstdio.h"
#include "gpfont.h"

GPDRAWSURFACE gpDraw;

void GpMain(void *arg)
{

	const char ScrollText[] = {"Welcome to my little textscroller for the GP32 handheld. Coded in C using the ARM SDT. Greetings to everyone in #gp32dev and #gp32.            ^_^           "};
	int i;
	int xcoord;
	unsigned int ticks;
	unsigned int newticks;
	unsigned char fcolor = 0;
	i = GpLcdSurfaceGet(&gpDraw, 0);  
	
	GpSurfaceSet(&gpDraw);	//make gpDraw with primary surface

	while(1)
	{
		xcoord=320;
		while(xcoord>-GpTextWidthGet( (char *)ScrollText))
		{	
			GpRectFill(NULL, &gpDraw, 0, 0, 320, 240, 0);
			GpTextOut(NULL, &gpDraw, xcoord, 125, (char*)ScrollText, fcolor);

			ticks=GpTickCountGet();

			while(ticks!=0)
			{
				newticks=GpTickCountGet();
				newticks-=ticks;
				if (newticks>10) ticks=0;
			}
			xcoord -=1;
			fcolor++;
		}
	}

}
