//
// decrypt.java
//  
//
// Created by Robert Laber on 3/7/12.
//  
// This file is the counterpart to the encrypt.java file.  Please see encrypt.java
// for details.  This class uses the modExp() and fileToCharArray() methods found
// in encrypt.java.

import java.util.*;
import java.io.*;

public class decrypt {
	
	// The makeFile() method takes a string of characters and produces a text file.
	
	public static void makeFile(char[] x, String fileName) throws IOException {

		String out = new String(x); // Converts the character array to a string.
		File f = new File("decrypted-"+fileName);
		Writer output = new BufferedWriter(new FileWriter(f));
		output.write(out); 			// Writes the file.
		output.close();
	}

	// The decrypt() method uses the modExp() method found in encrypt.java

	public static int[] decrypt(char[] p) {
	
		Scanner key = new Scanner(System.in);
		System.out.println("Enter decryption key:");
		int n = key.nextInt();  // only the value 418729 will work!
			
		int[] blockInts = new int[p.length/3];	
		
		for(int i=0; i<blockInts.length; i++) {
			
			// Recombine cypher characters into block of 3 by interpreting every 3
			// digits as base 94 expansion of a number between 0 and 94^3-1.
			
			blockInts[i] = (p[3*i]-32)*94*94 + (p[3*i + 1]-32)*94 + p[3*i + 2]-32;
			
			// Use decryption key n to decrypt
			
			blockInts[i] = encrypt.modExp(blockInts[i], n); 
		}
	
		int[] plain = new int[p.length];
		
		// For each entry in blockInts we compute the 3 digit base 74 expansion.
		// These will be the plaintext characters in our private alphabet.
	
		for(int i =0; i<blockInts.length; i++) {
			int y =blockInts[i];
			int first=0, second=0;
			
			while( 74*74 <= y) {
				first++;
				y-=(74*74);
			}
			
			while(74 <=y) {
				second++;
				y-=74;
			}
			
			plain[3*i] = (first );
			plain[3*i + 1] = (second );
			plain[3*i + 2] =(int) (y);
		}
		return plain;	
	}
	
	// The toChars() method is the counterpart of the toInts() method in encrypt.java
	// It converts private character values back to standard ACSCII values.
		
	public static char[] toChars(int[] x) {
	
		char[] p = new char[x.length];
		for(int i = 0; i<x.length; i++) {
		
			if(x[i] >=0 && x[i] <= 25)
				p[i] = (char) (x[i] + 97);
			
			if( x[i]>=26 && x[i] <= 51)
				p[i] = (char) (x[i] + 39);
				
			if(x[i] >= 52 && x[i] <= 61)
				p[i] = (char) (x[i] - 4);
					
			if(x[i] == 62)
				p[i] =  63;
			
			if(x[i] >= 63 && x[i] <= 65)
				p[i] = (char) (x[i] - 23);
					
			if(x[i] >= 66 && x[i]<= 69)
				p[i] = (char) (x[i] - 22);
					
			if(x[i] == 70 || x[i] == 71)
				p[i] = (char) (x[i] - 12);
					
			if(x[i] == 72)
				p[i]= 32;
				
			if(x[i] == 73)
				p[i] = 33;
		}
		return p;
	
	}

	// The main() method uses the fileToCharArray() method found in encrypt.java

	public static void main(String[] args) throws IOException {
		
		char[] in = encrypt.fileToCharArray(args[0]);
		int[] plainInts = decrypt(in);
		makeFile(toChars(plainInts), args[0]);
		System.out.println("\n"+"The file \""+args[0]+"\" has been decrypted!"+"\n");
	}
}
