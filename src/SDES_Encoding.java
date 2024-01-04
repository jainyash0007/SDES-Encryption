
public class SDES_Encoding 
{
	
	public static void main(String[] args)
	{
		Problem1();
	}
	private static void Problem1(){
		System.out.println("-------- Part 1 --------");

		byte[] key = { 0, 1, 1, 1, 0, 0, 1, 1, 0, 1 };
		String message = "CRYPTOGRAPHY";
		byte[] plaintext = CASCII.Convert(message);
		byte[] ciphertext = SDES.Encrypt(key, plaintext);

		System.out.println("Message:");
		System.out.println(message);
		System.out.println();

		System.out.println("Plaintext in CASCII bits:");
		Message_Encoding.printArray(plaintext);
		System.out.println();

		System.out.println("Ciphertext in CASCII bits: ");
		Message_Encoding.printArray(ciphertext);
		System.out.println();

		String bitOutput1 = CASCII.toString(ciphertext);
		System.out.println("Encrypted message:");
		System.out.println(bitOutput1);
		System.out.println();
	}
}
