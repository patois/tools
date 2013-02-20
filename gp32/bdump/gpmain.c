#include "gpdef.h"
#include "gpstdlib.h"
#include "gpgraphic.h"
#include "gpmain.h"
#include "gpstdio.h"
#include "gpfont.h"

GPDRAWSURFACE gpDraw;

void GpMain(void *arg)
{
	int i;
	ERR_CODE err_code;
	F_HANDLE h_file;
	unsigned long *BIOS = (unsigned long*)0x0;
	int ycoord = 10;
	
	i = GpLcdSurfaceGet(&gpDraw, 0);  
	
	GpSurfaceSet(&gpDraw);
	GpRectFill(NULL, &gpDraw, 0, 0, 320, 240, 0xFF);
	GpFatInit();	

	GpTextOut(NULL, &gpDraw, 10, ycoord, (char*)"Bios-Dump v0.11 by trapflag.", 0x0);
	ycoord +=10;

	err_code = GpRelativePathSet("gp:\\");
	if (err_code != SM_OK)
	{
		return;
	}
	
			
	err_code = GpDirCreate("BIOS", 0);
	if (err_code != SM_OK)
	{
		ycoord +=10;
		GpTextOut(NULL, &gpDraw, 10, ycoord, (char*)"Could not create directory 'BIOS'.", 0x0);
		while(1);
		return;
	}
	
	err_code = GpRelativePathSet("gp:\\BIOS");
	
	err_code = GpFileCreate("dump.bin", ALWAYS_CREATE, &h_file);
	if (err_code != SM_OK)
	{
		ycoord +=10;
		GpTextOut(NULL, &gpDraw, 10, ycoord, (char*)"File could not be created.", 0x0);
		while(1);
		return;
	}
	
	/* file writing ======================================================================
	*/
	GpTextOut(NULL, &gpDraw, 10, ycoord, (char*)"Please wait.. dumping now.", 0x0);

	err_code = GpFileWrite(h_file, BIOS, 0x00080000);
	if (err_code != SM_OK)
	{
		ycoord +=10;
		GpTextOut(NULL, &gpDraw, 10, ycoord, (char*)"Error.. couldnt dump BIOS.", 0x0);
		while(1);
		return;
	}
	ycoord +=10;

	GpFileClose(h_file);
	GpTextOut(NULL, &gpDraw, 10, ycoord, (char*)"Bios has been dumped. Please reset now.", 0x0);	
		
	while(1)
	;
}
