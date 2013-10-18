//
// encrypt.java
//  
//
// Created by Robert Laber on 3/5/12.
//
// This is a simple file encryption program.  The encryption is done using an RSA public
// key scheme.  Here, we use prime numbers p=1049 and q=757.  We then calculate their 
// product pq = 794,093 and the Euler Phi Function  phi(pq) = 792,288.  Our 'public' key 
// is the encryption exponent e=58777, and the 'private' decryption exponent is d=418729,
// so that e*d = 1 (mod phi(pq)).  The plain text is parsed into blocks of 3 characters.  
// We use a 74 character alphabet for the plaintext, and a 94 character alphabet for the 
// cyphertext.

import java.util.*;
import java.io.*;

public class encrypt {

	// The fileToCharArray() method allows us to import a text file for encryption, 
	// and returns an array of the characters from the file.
	
	public static char[] fileToCharArray(String fileName) {
		
		String s=""; // Initialize s to the empty String.
		try {
   			Scanner in = new Scanner(new File(fileName));
  			
			// Scan the whole file at once using delimiter \\z
			
			in.useDelimiter("\\z");
   			s=in.next();
 		} 
		catch (FileNotFoundException e) {
   			e.printStackTrace();
 		}
		return s.toCharArray();
 	}
	
	// The makeFile() method takes a array of characters and produces a text file.
	
	public static void makeFile(char[] x, String fileName) throws IOException {

		String out = new String(x); // Converts the character array to a string.
		File f = new File("encrypted-"+fileName);
		Writer output = new BufferedWriter(new FileWriter(f));
		output.write(out); 			// Writes the file.
		output.close();
	}
	
	// The next method, toInts(), does two things.  First, it extends the input array to 
	// have length divisible by 3, since our cryptosystem uses blocks of size 3.
	// Second, it converts the standard ASCII character values into private character 
	// values from 0 to 73.  Explicitly, our alphabet is as follows:
	//
	// a-z have values 0-25
	// A-Z have values 26-51
	// 0-9 have values 52-61
	// ? has value 62	
	// ( and ) have values 63 and 64, respectively
	// * has value 65
	// , has value 66
	// - has value 67
	// . has value 68
	// / has value 69
	// : has value 70
	// ; has value 71
	// Space has value 72
	// ! has value 73
	
	
	public static int[] toInts(char[] p) {
		
		int n; // n is the length of the output array, which will be divisible by 3.
		
		if(p.length % 3 == 0)
			n=p.length;
		else
			n=p.length + 3-(p.length % 3);
		
		// x will be our output array.  It is an array of integers which correspond 
		// to the characters of the input array using our private character values.
		
		int[] x = new int[n]; 
	
		for (int i =0; i<x.length; i++) {
		
			if( i<p.length) {
				if( p[i] >=97 && p[i] <= 122) // lower case letters are 0-25
					x[i] = p[i]-97;
			
				if( p[i] >= 65 && p[i] <= 90) // capital letters are 26-51
					x[i] = p[i] - 39;
			
				if( p[i] >= 48 && p[i] <= 57) // digits 0-9 are 52-61
					x[i] = p[i] +4;
			
				if( p[i] == 63)				 // ? is 62
					x[i] = 62;
				
				if( p[i] >= 40 && p[i] <= 42) // ( , ) and * are 63,64, and 65, resp.
					x[i] = p[i] +23;	
				
				if( p[i] >= 44 && p[i] <= 47) // other misc symbols are 66-69
					x[i] = p[i] +22;
			
				if( p[i] == 58 || p[i] == 59) // : is 70 and ; is 71
					x[i] = p[i] + 12;		
				
				if( p[i] == 32)				// space is 72
					x[i] = 72;
			
				if( p[i] == 33)				// ! is 73
					x[i] = 73;	
			}
			else
				x[i] = 72;	// initialize extra entries to space		
		
		}
		return x;
	}
	
	// The modExp() method computes the residue class of a^b mod 794093.  We make use 
	// of the fact that the operation of taking residues commutes with 
	// multiplication, i.e., (a*b) mod c  =  (a*(b mod c)) mod c.
	
	public static int modExp(int a , int b) {
		long x=1; 				// Value x may get larger than an int
		for (int i=0; i<b ; i++) {
			x*= a;
			x= x % 794093;   // The number 794093 is p*q as defined in the header
		}
		return (int)x;	
	}
	
	// The encrypt() method takes an array of integers corresponding to the plaintext 
	// message.  It converts this into an array of longs 1/3 the length of the input 
	// array by interpreting every three digits of the input array as the base 74 
	// representation of an integer between 0 and 74^3 - 1.  It then computes the 
	// residue class of each entry raised to the 58777 power mod 794093, and returns 
	// the corresponding array.
	
	public static int[] encrypt(int[] p) {
	
		int[] blockInts = new int[p.length/3];
		
		for (int i=0; i<blockInts.length; i++) {
			blockInts[i] = p[3*i]*74*74 + p[3*i + 1]*74 + p[3*i + 2];
			
			// Note that the value 58777 below corresponds to a public key value.
			// For multiple users we would need distinct values here.
			
			blockInts[i] = modExp(blockInts[i], 58777);
		}	
		return blockInts;
	}
	
	
	// The toCypherText() method takes an array of longs and creates an array 3 
	// times as longs by converting every element of the input array into its 
	// base 94 expansion.  Since the elements of the input array are residue classes 
	// mod 794093, and 94^3 > 794093, we can be sure that each expansion into base 94 
	// needs only 3 digits.  The number 94 corresponds to the number of ASCII values 
	// between 32 and 125, which are the interesting ones for an output file.
	
	public static char[] toCypherText(int[] x) {
		
		char[] cypherChars = new char[3*x.length]; // This will be the output array.
		
		for(int i =0; i<x.length; i++) {
			
			// The ints 'first' and 'second' are the coefficients of 94^2 and 94, 
			// respectively, in the base 94 expansion of the i-th entry of the input array.
			
			int first=0, second=0; 
			
			int y=x[i]; // Declare local variable equal to the i-th entry.
			
			// Next compute the base 94 representation of y.
			
			while( 94*94 <= y) {
				first++;
				y-=(94*94);
			}
			
			while(94 <=y) {
				second++;
				y-=94;
			}
			
			// Now we can initailize the output array.  We add 32 to each entry to 
			// make sure we get meaningful ASCII values.
			
			cypherChars[3*i] =(char) (first + 32);
			cypherChars[3*i + 1] =(char) (second + 32);
			cypherChars[3*i + 2] =(char) (y + 32);
		}
		
		// The cypherChars[] array is now an array consisting of characters with 
		// ASCII values between 32 and 125.  
		// This array is effectively the cypher text.
		
		return cypherChars;	
	}

	public static void main(String[] args) throws IOException  {
	
		char[] plainText = fileToCharArray(args[0]);
		
		int[] plainInts = toInts(plainText);
		
		int[] cypherInts = encrypt(plainInts);
		
		char[] cypherText = toCypherText(cypherInts);
		
		makeFile(cypherText, args[0]);
		System.out.println("\n"+"The file \""+args[0] +"\" has been encrypted!");
		System.out.println("The encrypted file is saved as \'encrypted-"+args[0]+"\'\n");
		
	}
}



