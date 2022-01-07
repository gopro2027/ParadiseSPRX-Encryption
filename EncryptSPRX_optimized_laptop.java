package com.main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;

//The bin folder needs to be copied to the project location for this to work, or I can change the batch file back... whatever i shouldn't be messing with this anymore anyways

public class EncryptSPRX_optimized_laptop {
	
	public static int findIndexOf(byte[] in, int start, byte[] find) {
		int lengthOfFind = find.length;
		int inLength = in.length;
		int currentStartPos = start;
		int currentSpotInFind = 0;
		for (int i = start; i < inLength; i++) {
			if (in[i] == find[currentSpotInFind]) {
				//if (currentSpotInFind == 0)
				//	currentStartPos = i;
				currentSpotInFind++;
				if (currentSpotInFind == lengthOfFind)
					return currentStartPos+1;
			} else {
				currentStartPos++;
				i = currentStartPos;
				currentSpotInFind = 0;
			}
		}
		return -1;
	}
	

	public static String mainLoc = "ParadiseGTA_optimized_2020";
	public static String inLoc = "D:/"+mainLoc+"/PS3_Debug/utils/ParadiseGTA.prx";
	public static String outLoc = "D:/"+mainLoc+"/PS3_Debug/utils/ParadiseGTA.prx.e";
	public static String outLocSPRX = "D:/"+mainLoc+"/PS3_Debug/utils/ParadiseGTA.sprx";
	
	public static void doLastPart() throws IOException {
		
		
		
		
		
		//sign the encrypted one
		
		/*
		ProcessBuilder builder = new ProcessBuilder(
	            "cd", 
	            "/d", 
	            "E:\\"+mainLoc+"\\PS3_Debug\\utils\\",
	            "&&",
	            "make_fself",
	            "ParadiseGTA.prx.e",
	            "ParadiseGTA.sprx"
				);
	        builder.redirectErrorStream(true);
	        Process p = builder.start();
	        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
	        String line;
	        while (true) {
	            line = r.readLine();
	            if (line == null) { break; }
	            System.out.println(line);
	        }
	        */
		//Runtime.getRuntime().exec("cmd cd /d E:\\"+mainLoc+"\\PS3_Debug\\utils\\ && make_fself ParadiseGTA.prx.e ParadiseGTA.sprx");
		
		
		ProcessBuilder builder = new ProcessBuilder(
		         "cmd.exe", "/c", "cd D:\\"+mainLoc+"\\PS3_Debug\\utils\\ && make_fself D:\\"+mainLoc+"\\PS3_Debug\\utils\\ParadiseGTA.prx.e D:\\"+mainLoc+"\\PS3_Debug\\utils\\ParadiseGTA.sprx");
			builder.redirectErrorStream(true);
	        Process p = builder.start();
	        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
	        String line;
	        while (true) {
	            line = r.readLine();
	            if (line == null) { break; }
	            System.out.println(line);
	        }
		
		
		
		
		RandomAccessFile f = new RandomAccessFile(outLocSPRX, "r");
		byte[] data = new byte[(int)f.length()];
		f.readFully(data);
		data[0xB7] = (byte) 0x80;//patch it
		try (FileOutputStream fos = new FileOutputStream(outLocSPRX)) {
		   fos.write(data);
		   System.out.println("Successful!\n");
		}
		f.close();
	}
	
	int little2big(int i) {
	    return (i&0xff)<<24 | (i&0xff00)<<8 | (i&0xff0000)>>8 | (i>>24)&0xff;
	}
	
	static int dataSegmentStart = 0;
	static int dataSegmentSize = 0;
	
	public static void encryptDataSegment(byte[] data) {
		char key[] = {0x27, 0xC5, 0x8B, 0x13, 0xA8, 0x97, 0x4B, 0xCB, 0x0C, 0x1F, 0x47, 0xEB, 0x37, 0x4F, 0xEE, 0xE0, 0x7D, 0xFB, 0x0D, 0x91, 0xE4, 0xB1, 0x07, 0x4A, 0x58, 0xE0, 0x19, 0x36, 0x31, 0x01, 0x86, 0x59, 0xC6, 0x11, 0x6C};
		for (int i = 0; i < dataSegmentSize; i++) {
			data[dataSegmentStart+i] = (byte) (data[dataSegmentStart+i] ^ key[i%key.length]);
		}
	}
	
	public static void main(String[] args) {
		try { 
			RandomAccessFile f = new RandomAccessFile(inLoc, "r");
			byte[] data = new byte[(int)f.length()];
			
			
			 IntBuffer intBuf =
					   ByteBuffer.wrap(data)
					     .order(ByteOrder.BIG_ENDIAN)
					     .asIntBuffer();
					 //int[] dataInt = new int[intBuf.remaining()];
					 //intBuf.get(dataInt);
			
			f.readFully(data);
			int idaAlignAddress = 0x670;
			int p_flagsOffsetFromElf = 0x47;
			int dataSegmentStartOffset = 0x8C;
			int dataSegmentSizeOffset = 0xA4;
			byte elfHeaderSig[] = {(byte)0x7F ,(byte)0x45 ,(byte)0x4C ,(byte)0x46};
			int indexP_Flags = p_flagsOffsetFromElf;//findIndexOf(data,elfHeaderSig)+p_flagsOffsetFromElf;
			if (data[indexP_Flags] != 0x5) {
				System.out.println("Unexpected seg flags!");
			} else {
				data[indexP_Flags] = 0x7;//0x7 is all, 0x5 is default for read and execute. This does set segment info in ida properly. This is for PPU
				
				dataSegmentStart = intBuf.get(dataSegmentStartOffset/0x4);
				dataSegmentSize = intBuf.get(dataSegmentSizeOffset/0x4);
				
				/*for (int i = 0; i < (dataSegmentStartOffset+1)/4; i++) {
					System.out.print(String.format("%08X", data[i])+" ");
				}
				System.out.println("\n"+String.format("0x%08X", intBuf.get(0)));*/
				System.out.println(""+String.format("0x%08X", dataSegmentStart)+" "+String.format("0x%08X", dataSegmentSize));
				
				//data[indexP_Flags-2] = 0x70;//This is SPU flags. It does not load with anything other than 0x40 however, and yes it is 0x40 not 0x4
				//0x7F is second segment flag
				//data[0x7F] = 0x7;//this is the second smaller segment
				System.out.println("Set seg flags!");
			}
			
			//encryptDataSegment(data);
			
			//key I use
			byte key[] = {(byte)0x32,(byte)0x11,(byte)0x07,(byte)0x8a,(byte)0xe9,(byte)0x5b,(byte)0x90,(byte)0xc3,(byte)0x06,(byte)0x02,(byte)0x8e,(byte)0x78,(byte)0x09,(byte)0x8e,(byte)0xb2,(byte)0x24,(byte)0xd4,(byte)0xd1,(byte)0x14,(byte)0x06,(byte)0x81,(byte)0x34,(byte)0x76,(byte)0xe7,(byte)0x7e,(byte)0x30,(byte)0x28,(byte)0xc1,(byte)0x6d,(byte)0xfb,(byte)0x59,(byte)0x3c,(byte)0x9f,(byte)0x3d,(byte)0x9d,(byte)0xa8,(byte)0x8f,(byte)0x3a,(byte)0x85,(byte)0x2d,(byte)0x4d,(byte)0x53,(byte)0xe6,(byte)0x9b,(byte)0xed,(byte)0xfb,(byte)0xf2,(byte)0x01,(byte)0x24,(byte)0x0c,(byte)0xcf,(byte)0x53,(byte)0x7e,(byte)0x74,(byte)0x42,(byte)0xfa,(byte)0x86};
			
			
			//do function specific encryption
			
			byte findBytesStart[] = {(byte)0x7C,(byte)0x63,(byte)0x22,(byte)0x78,(byte)0x7C,(byte)0x63,(byte)0x22,(byte)0x78};
			byte findBytesEnd[] =   {(byte)0x7C,(byte)0x63,(byte)0x2A,(byte)0x78,(byte)0x7C,(byte)0x63,(byte)0x2A,(byte)0x78};
			int indexStart = 0;
			int indexEnd = 0;
			int startFindIndex = 0;
			while (indexStart != -1 && indexEnd != -1) {
				//System.out.println("Start index: "+startFindIndex);
				indexStart = findIndexOf(data,startFindIndex, findBytesStart)+0x8;
				indexEnd = findIndexOf(data,startFindIndex, findBytesEnd);
				System.out.println("fstart: "+indexStart+" fend: "+indexEnd);
				if (indexStart != -1 && indexEnd != -1) {
					if (indexStart > indexEnd) {
						System.out.println("ERROR! Start index after end index");
					}
					//reverse it
					/*int lengthOfIt = indexEnd-indexStart;
					for (int i = 0; i < lengthOfIt/2-4; i++) {
						if ((indexStart+i)%4 == 0 || (indexStart+i)%4 == 1) {
							byte tmpData = data[indexStart+i];
							data[indexStart+i] = data[indexEnd-3-i];
							data[indexEnd-3-i] = tmpData;
						}
					}*/
					//encrypt it
					for (int i = indexStart; i < indexEnd; i++) {
						if (i%4 == 0 || i%4 == 1) {
							data[i] = (byte) ((byte)data[i]^key[(i-indexStart)%key.length]);
						}
					}
					
					
				}
				startFindIndex = indexEnd+8;
			}
			
			
			
			
			
			
			//do the QUICK function specific encryption
			findBytesStart = new byte[]{(byte)0x7C,(byte)0x63,(byte)0x32,(byte)0x78,(byte)0x7C,(byte)0x63,(byte)0x32,(byte)0x78};
			findBytesEnd =   new byte[]{(byte)0x7C,(byte)0x63,(byte)0x3A,(byte)0x78,(byte)0x7C,(byte)0x63,(byte)0x3A,(byte)0x78};
			indexStart = 0;
			indexEnd = 0;
			startFindIndex = 0;
			while (indexStart != -1 && indexEnd != -1) {
				//System.out.println("Start index: "+startFindIndex);
				indexStart = findIndexOf(data,startFindIndex, findBytesStart)+0x8;
				indexEnd = findIndexOf(data,startFindIndex, findBytesEnd);
				System.out.println("fqstart: "+indexStart+" fqend: "+indexEnd);
				if (indexStart != -1 && indexEnd != -1) {
					if (indexStart > indexEnd) {
						System.out.println("ERROR! Start index after end index");
					}
					
					//encrypt it
					for (int i = indexStart; i < indexEnd; i++) {
						if (i%4 == 0 || i%4 == 1) {
							data[i] = (byte) ((byte)data[i]^key[(i-indexStart)%key.length]);
						}
					}
					
					//reverse it
					/*int lengthOfIt = indexEnd-indexStart;
					for (int i = 0; i < lengthOfIt/2-4; i++) {
						if ((indexStart+i)%4 == 0 || (indexStart+i)%4 == 1) {
							byte tmpData = data[indexStart+i];
							data[indexStart+i] = data[indexEnd-3-i];
							data[indexEnd-3-i] = tmpData;
						}
					}*/
					
				}
				startFindIndex = indexEnd+8;
			}
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			//do whole memory encryption
			findBytesStart = new byte[]{(byte)0x3C,(byte)0x60,(byte)0xFF,(byte)0xEE,(byte)0x60,(byte)0x63,(byte)0xDD,(byte)0xCC};
			findBytesEnd = new byte[]{(byte)0x3C,(byte)0x60,(byte)0xFF,(byte)0xEE,(byte)0x60,(byte)0x63,(byte)0xDD,(byte)0xCD};
			indexStart = 0;
			indexEnd = 0;
			startFindIndex = 0;
			while (indexStart != -1 && indexEnd != -1) {
				//System.out.println("Start index: "+startFindIndex);
				indexStart = findIndexOf(data,startFindIndex, findBytesStart)+0x8;
				indexEnd = findIndexOf(data,startFindIndex, findBytesEnd);
				System.out.println("start: "+indexStart+" end: "+indexEnd);
				
				if (indexStart != -1 && indexEnd != -1) {
					if (indexStart > indexEnd) {
						System.out.println("ERROR! Start index after end index");
					}
					//encrypt it
					for (int i = indexStart; i < indexEnd; i++) {
						if (i%4 == 0 || i%4 == 1) {
							data[i] = (byte) ((byte)data[i]^key[(i-indexStart)%key.length]);
						}
					}
					//reverse it
					int lengthOfIt = indexEnd-indexStart;
					for (int i = 0; i < lengthOfIt/2-4; i++) {
						if ((indexStart+i)%4 == 0 || (indexStart+i)%4 == 1) {
							//System.out.println(((indexStart+i)%4)+" "+((indexEnd-3-i)%4));
							byte tmpData = data[indexStart+i];
							data[indexStart+i] = data[indexEnd-3-i];
							data[indexEnd-3-i] = tmpData;
						}
					}
					
					//minus bytes
					byte key2[] = new byte[76];//{0xd7, 0xad, 0x6a, 0x5d, 0x65, 0x00, 0xde, 0xdd, 0xb3, 0x7e, 0x67, 0x00, 0xb3, 0x26, 0x53, 0xfa, 0x1d, 0x80, 0x74, 0x08, 0x9b, 0xaa, 0x6b, 0xaa, 0xc8, 0x6f, 0x57, 0xbf, 0x01, 0x5b, 0x95, 0x75, 0x04, 0x08, 0x3a, 0x28, 0x7f, 0x90, 0x32, 0xee, 0x34, 0x9e, 0x33, 0xb0, 0xc1, 0x07, 0xa7, 0x5f, 0xf6, 0x4a, 0x0c, 0x55, 0xe0, 0xd8, 0xf9, 0xf3, 0x2f, 0x54, 0x0d, 0xea, 0x6d, 0x15, 0x1a, 0xa3, 0x01, 0xe3, 0xcc, 0x63, 0xd7, 0xc2, 0x60, 0x3a, 0x24, 0xb7, 0xbc, 0x01};
					key2[0] = (byte)0xD7;key2[1] = (byte)0xAD;key2[2] = (byte)0x6A;key2[3] = (byte)0x5D;key2[4] = (byte)0x65;key2[5] = (byte)0x0;key2[6] = (byte)0xDE;key2[7] = (byte)0xDD;key2[8] = (byte)0xB3;key2[9] = (byte)0x7E;key2[10] = (byte)0x67;key2[11] = (byte)0x0;key2[12] = (byte)0xB3;key2[13] = (byte)0x26;key2[14] = (byte)0x53;key2[15] = (byte)0xFA;key2[16] = (byte)0x1D;key2[17] = (byte)0x80;key2[18] = (byte)0x74;key2[19] = (byte)0x8;key2[20] = (byte)0x9B;key2[21] = (byte)0xAA;key2[22] = (byte)0x6B;key2[23] = (byte)0xAA;key2[24] = (byte)0xC8;key2[25] = (byte)0x6F;key2[26] = (byte)0x57;key2[27] = (byte)0xBF;key2[28] = (byte)0x1;key2[29] = (byte)0x5B;key2[30] = (byte)0x95;key2[31] = (byte)0x75;key2[32] = (byte)0x4;key2[33] = (byte)0x8;key2[34] = (byte)0x3A;key2[35] = (byte)0x28;key2[36] = (byte)0x7F;key2[37] = (byte)0x90;key2[38] = (byte)0x32;key2[39] = (byte)0xEE;key2[40] = (byte)0x34;key2[41] = (byte)0x9E;key2[42] = (byte)0x33;key2[43] = (byte)0xB0;key2[44] = (byte)0xC1;key2[45] = (byte)0x7;key2[46] = (byte)0xA7;key2[47] = (byte)0x5F;key2[48] = (byte)0xF6;key2[49] = (byte)0x4A;key2[50] = (byte)0xC;key2[51] = (byte)0x55;key2[52] = (byte)0xE0;key2[53] = (byte)0xD8;key2[54] = (byte)0xF9;key2[55] = (byte)0xF3;key2[56] = (byte)0x2F;key2[57] = (byte)0x54;key2[58] = (byte)0xD;key2[59] = (byte)0xEA;key2[60] = (byte)0x6D;key2[61] = (byte)0x15;key2[62] = (byte)0x1A;key2[63] = (byte)0xA3;key2[64] = (byte)0x1;key2[65] = (byte)0xE3;key2[66] = (byte)0xCC;key2[67] = (byte)0x63;key2[68] = (byte)0xD7;key2[69] = (byte)0xC2;key2[70] = (byte)0x60;key2[71] = (byte)0x3A;key2[72] = (byte)0x24;key2[73] = (byte)0xB7;key2[74] = (byte)0xBC;key2[75] = (byte)0x1;
					for (int i = 0; i < lengthOfIt; i++) {
						if ((indexStart+i)%4 == 0 || (indexStart+i)%4 == 1) {
							data[indexStart+i]-=key2[i%key2.length];
						}
					}
					
					
				}
				startFindIndex = indexEnd+8;
			}
			
			
			try (FileOutputStream fos = new FileOutputStream(outLoc)) {
			   fos.write(data);
			   System.out.println("Successful!\n");
			}
			f.close();
			
			//now ressign the sprx and then modify segment header
			doLastPart();
			
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

}
