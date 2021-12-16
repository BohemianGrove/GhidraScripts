//Created by @RealFrogPoster

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

import java.io.File;
import java.io.FileWriter;
import java.util.Set;

import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;

public class IATFuncLink extends GhidraScript {

	@Override
	protected void run() throws Exception {
		//Checking if currentProgram is valid... This means script ran with no plugins loaded. Currentprogram is a global variable provided by the flatapi/ghidrascript
		if(currentProgram == null)
			return;
		
		//Our stringbuilder for our output
		StringBuilder sBuilder = new StringBuilder();
		//Grabbing symboltable for later
		SymbolTable SymTable = currentProgram.getSymbolTable();
		
		//Getting imports
		SymbolIterator ImportTable = SymTable.getExternalSymbols();
		//Looping iat
		for(Symbol i : ImportTable)
		{
			//Checking if the symbol is in ntdll
			if(i.getParentSymbol().getName().equalsIgnoreCase("ntdll.dll"))
			{
				//Getting xrefs to the import (Functions that use it)
				//Monitor is a global variable
				Set<Address> XRefs = ReferenceUtils.getReferenceAddresses(i.getProgramLocation(), monitor);
				
				sBuilder.append("Symbol " + i.getName() + " usage\n");
				//Looping xrefs
				for(Address Ref : XRefs)
				{
					Function CurSym = currentProgram.getFunctionManager().getFunctionContaining(Ref);
					if(CurSym == null)
						continue;
					//Subtracting import addr - function addr. Giving us the offset of the import call.
					Long lImportOffset = toAddr(Ref.getOffset()).subtract(CurSym.getEntryPoint().getOffset()).getOffset();
					String szImportOffset = new String();
					//Removing leading 0's, as it's n chars, where n is the architecture ptr size.
					if(lImportOffset != 0)
						szImportOffset = Long.toHexString(lImportOffset).replaceFirst ("^0*", "");
					else //If it's already 0 we would wipe the string, so just setting it to 0
						szImportOffset = "0";
					sBuilder.append("\t" + CurSym.getName() + " + 0x" + szImportOffset + "\n");
				}
				
			}
		}
		
		try
		{
			//Opening file to write to
			FileWriter outFile = new FileWriter("ImportFile.txt");
			outFile.write(sBuilder.toString());
			return;
		
		}
		catch(Exception e)
		{
			println("IATFuncLink: Cannot create file!\n");
			return;
		}
	
	}
}
