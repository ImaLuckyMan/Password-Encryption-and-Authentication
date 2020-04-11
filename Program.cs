using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace EncryptedPassword
{
	class Hash
	{
		
		static void Main(string[] args)
		{
			// Generate a new random password string
			string myPassword = Password.CreateRandomPassword(8);
			Console.WriteLine("My Password is: " + myPassword);

			Console.WriteLine("Please enter a password: ");
			string _password = Console.ReadLine();

			// Debug output
			Console.WriteLine("Your origional Password was : " + _password);
			//Console.Write("Your new hashed salted password is : ");

			// Generate a new random salt
			int mySalt = Password.CreateRandomSalt();
			Console.WriteLine("Your new salt is : " + mySalt);

			// Initialize the Password class with the password and salt
			Password pwd = new Password(_password, mySalt);
			
			// Compute the salted hash
			// NOTE: you store the salt and the salted hash in the datbase
			string strHashedPassword = pwd.ComputeSaltedHash();
			Console.WriteLine("The new stored Hashed Password is : " + strHashedPassword);

			// Debug output
			Console.WriteLine(strHashedPassword);

			
		}
	

		public class Password
		{
			private string _password;
			private int _salt;
			private object sha1;

			public Password(string strPassword, int nSalt)
			{
				_password = strPassword;
				_salt = nSalt;
			}

			public static string CreateRandomPassword(int PasswordLength)
			{
			String _allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789";
			Byte[] randomBytes = new Byte[PasswordLength];
			Random random = new Random();
			random.NextBytes(randomBytes);
			char[] chars = new char[PasswordLength];
			int allowedCharCount = _allowedChars.Length;
			
			for (int i = 0; i < PasswordLength; i++)
			{
			chars[i] = _allowedChars[(int)randomBytes[i] % allowedCharCount];
			}

			return new string(chars);
			}

			public static int CreateRandomSalt()
			{
				Byte[] _saltBytes = new Byte[4];
				Random random = new Random();
				random.NextBytes(_saltBytes);
				return ((((int)_saltBytes[0]) << 24) + (((int)_saltBytes[1]) << 16) +
					(((int)_saltBytes[2]) << 8) + ((int)_saltBytes[3]));
			}

			public string ComputeSaltedHash()
			{
				// Create Byte array of password string
				ASCIIEncoding encoder = new ASCIIEncoding();
				Byte[] _secretBytes = encoder.GetBytes(_password);

				// Create a new salt
				Byte[] _saltBytes = new Byte[4];
				_saltBytes[0] = (byte)(_salt >> 24);
				_saltBytes[1] = (byte)(_salt >> 16);
				_saltBytes[2] = (byte)(_salt >> 8);
				_saltBytes[3] = (byte)(_salt);

				// append the two arrays
				Byte[] toHash = new Byte[_secretBytes.Length + _saltBytes.Length];
				Array.Copy(_secretBytes, 0, toHash, 0, _secretBytes.Length);
				Array.Copy(_saltBytes, 0, toHash, _secretBytes.Length, _saltBytes.Length);

				//SHA1 sha1 = SHA1.Create();
				Byte[] computedHash = toHash;

				return encoder.GetString(computedHash);
			}
		}
	}
}

// retrieve salted hash and salt from user database, based on username

//Password pwd = new Password(txtPassword.Text, nSaltFromDatabase);

//if (pwd.ComputeSaltedHash() == strStoredSaltedHash)
//{
   // user is authenticated successfully
//}
//else
//{